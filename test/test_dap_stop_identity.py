"""Internal loader guards need exact owner proof and atomic conditional resume."""
import time
from test_dap_deferred_loader_stop import session, state, set_function, changed, stopped, no_stop


def settled(client, predicate):
    # The event reader may not have queued the worker when the set response
    # arrives. Observe only the synthetic fixture, with a bounded deadline.
    deadline = time.monotonic() + 3
    while True:
        value = state(client)
        if predicate(value):
            return value
        assert time.monotonic() < deadline, value
        time.sleep(0.01)


def run():
    for mode in ("deferred-id-normal", "deferred-id-no-hold", "deferred-id-released-short"):
        with session(mode) as client:
            bp = set_function(client)[0]
            assert not bp["verified"], bp
            changed(client, bp["id"])
            # Receiving the response requires the worker transaction to finish.
            value = settled(client, lambda v: v["n"] == 1 and v["h"] == 0 and v["c"] == 0)
            assert value["a"] == (0 if mode.endswith("no-hold") else 1), value
            assert value["s"] == 9007199254740993, value
            no_stop(client)
            assert set_function(client, ()) == []

    # A failed BP installation still releases only our internal guard, so the
    # loader can progress; it does not manufacture a verified breakpoint.
    with session("deferred-id-reject") as client:
        assert not set_function(client)[0]["verified"]
        settled(client, lambda v: v["n"] == 1 and v["a"] == 1 and v["h"] == 0 and v["c"] == 0)
        no_stop(client)

    for mode in ("deferred-id-user", "deferred-id-unknown", "deferred-id-new-sequence",
                 "deferred-id-legacy-event", "deferred-id-legacy-query",
                 "deferred-id-no-cap", "deferred-id-partial"):
        with session(mode) as client:
            bp = set_function(client)[0]
            changed(client, bp["id"])
            stopped(client)
            value = settled(client, lambda v: v["n"] == 0 and v["a"] == 0 and v["h"] == 1 and v["c"] == 0)
            if mode in ("deferred-id-no-cap", "deferred-id-partial"):
                assert value["i"] == 0 and value["l"] > 0, value
            else:
                assert value["i"] > 0, value

    with session("deferred-id-visible") as client:
        bp = set_function(client)[0]
        changed(client, bp["id"])
        stopped(client)
        settled(client, lambda v: v["n"] == 0 and v["h"] == 1 and v["c"] == 0)
        no_stop(client)  # a later identity must not auto-release a visible pause

    with session("deferred-id-other-thread") as client:
        bp = set_function(client)[0]
        exception = client.event("stopped", timeout=3, predicate=lambda event:
            event["body"]["reason"] == "exception")
        assert exception["body"]["threadId"] == 88
        changed(client, bp["id"])
        settled(client, lambda v: v["n"] == 1 and v["a"] == 1 and v["h"] == 0 and v["e"] == 1 and v["c"] == 0)
        no_stop(client)  # only the guard thread was resumed

    # Replacement during BP installation and in the query->release window must
    # leave the actual exception stopped, without a misleading loader pause.
    for mode in ("deferred-id-during", "deferred-id-race", "deferred-id-restop"):
        with session(mode) as client:
            bp = set_function(client)[0]
            exception = client.event("stopped", timeout=3, predicate=lambda event:
                event["body"]["reason"] == "exception")
            assert exception["body"]["threadId"] == 77
            changed(client, bp["id"])
            value = settled(client, lambda v: v["h"] == 1 and v["c"] == 0)
            assert value["n"] == (0 if mode.endswith("during") else 1), value
            assert value["a"] == (1 if mode.endswith("restop") else 0), value
            no_stop(client)

    for mode in ("deferred-id-error", "deferred-id-short", "deferred-id-same-reply",
                 "deferred-id-race-no-event"):
        with session(mode) as client:
            bp = set_function(client)[0]
            changed(client, bp["id"])
            stopped(client)
            value = settled(client, lambda v: v["n"] == 1 and v["a"] == 0 and v["h"] == 1 and v["c"] == 0)
            assert value["s"] == 9007199254740993, value
            if mode != "deferred-id-race-no-event":
                client.event("output", timeout=3, predicate=lambda event:
                    "not confirmed" in event["body"].get("output", ""))

    with session("deferred-id-query-short") as client:
        assert not set_function(client)[0]["verified"]
        client.event("output", timeout=3, predicate=lambda event:
            "could not be confirmed" in event["body"].get("output", ""))
        settled(client, lambda v: v["n"] == 0 and v["c"] == 0 and v["h"] == 1)
        no_stop(client)
    print("PASS stop identity opt-in, exact >2^53 token, guard ownership, atomic races, rapid restop, malformed outcomes and legacy fallback")


if __name__ == "__main__":
    run()
