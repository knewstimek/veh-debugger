"""Bind at a confirmed guest stop; never resume a hold without identity."""
from contextlib import contextmanager
from pathlib import Path

from build_paths import RELEASE
from dap_test_client import DapClient


@contextmanager
def session(mode):
    client = DapClient(str(Path(RELEASE) / "veh-debug-adapter.exe"))
    try:
        client.initialize()
        response = client.request("attach", {
            "targetScope": "guest", "processId": 4242,
            "agent": str(Path(RELEASE) / "guest_backend_fixture.exe"),
            "agentArgs": ["--metadata", mode],
        })
        assert response["success"], response
        yield client
    finally:
        client.close(terminate_debuggee=False)


def state(client):
    response = client.request("threads")
    assert response["success"], response
    name = response["body"]["threads"][0]["name"]
    return {key: int(value) for key, value in (part.split("=") for part in name.split(","))}


def set_function(client, names=("sample!DeferredFunction",)):
    response = client.request("setFunctionBreakpoints", {
        "breakpoints": [{"name": name} for name in names],
    })
    assert response["success"], response
    return response["body"]["breakpoints"]


def changed(client, bp_id):
    event = client.event("breakpoint", timeout=3, predicate=lambda message:
                         message["body"].get("reason") == "changed" and
                         message["body"]["breakpoint"]["id"] == bp_id)
    assert event["body"]["breakpoint"]["verified"], event


def stopped(client, tid=77):
    event = client.event("stopped", timeout=3, predicate=lambda item:
                         item["body"].get("reason") == "pause" and item["body"]["threadId"] == tid)
    assert not event["body"]["allThreadsStopped"], event
    return event


def no_stop(client):
    try:
        event = client.event("stopped", timeout=0.15)
    except TimeoutError:
        return
    raise AssertionError(("Invented or overwritten stop", event))


def run():
    for mode in ("deferred-normal", "deferred-stale"):
        with session(mode) as client:
            bp = set_function(client)[0]
            assert not bp["verified"], bp
            changed(client, bp["id"])
            stopped(client)
            current = state(client)
            assert current["res"] == 0 and current["held"] == 1 and current["g"] == 1, current
            assert client.request("continue", {"threadId": 77, "singleThread": True})["success"]
            assert state(client)["held"] == 0
            assert client.request("readMemory", {"memoryReference": "0x2000", "count": 1})["success"]
            changed(client, bp["id"])
            stopped(client)
            current = state(client)
            assert current["res"] == 1 and current["held"] == 1, current
            assert set_function(client, ()) == []
            assert state(client)["g"] == 0

    with session("deferred-reject") as client:
        assert not set_function(client)[0]["verified"]
        held = stopped(client)
        assert "pending" in held["body"]["description"], held
        assert state(client)["c"] == 0
        assert set_function(client)[0]["verified"], "Failed installation was not retryable"
        assert state(client)["c"] == 0

    for mode in ("deferred-user-stop", "deferred-during"):
        with session(mode) as client:
            bp = set_function(client)[0]
            exception = client.event("stopped", predicate=lambda event: event["body"]["reason"] == "exception")
            assert exception["body"]["threadId"] == 88
            changed(client, bp["id"])
            stopped(client)
            assert state(client)["c"] == 0
            installed = client.request("setInstructionBreakpoints", {
                "breakpoints": [{"instructionReference": "0x1100"}],
            })
            assert installed["success"] and installed["body"]["breakpoints"][0]["verified"], installed
            assert set_function(client, ()) == []
            current = state(client)
            assert current["g"] == 0 and current["rm"] == 0 and current["c"] == 0, current

    with session("deferred-same-tid") as client:
        bp = set_function(client)[0]
        exception = client.event("stopped", predicate=lambda event: event["body"]["reason"] == "exception")
        assert exception["body"]["threadId"] == 77
        changed(client, bp["id"])
        assert state(client)["c"] == 0
        no_stop(client)  # current exception reason must not become an old loader reason

    # Deterministic review regression: an old hold arrives during Continue,
    # then is consumed by that request before its acknowledgement is sent.
    with session("deferred-queued-release") as client:
        assert not set_function(client)[0]["verified"]
        client.event("stopped", predicate=lambda event: event["body"]["reason"] == "exception")
        assert client.request("continue")["success"]
        client.event("module", predicate=lambda event: event["body"]["reason"] == "removed")
        current = state(client)
        assert current["c"] == 1 and current["q"] == 1 and current["set"] == 0 and current["held"] == 0, current
        no_stop(client)

    # A genuine new hold also arrives before the acknowledgement. It must be
    # confirmed and exposed, never dropped merely because of arrival timing.
    with session("deferred-queued-new") as client:
        bp = set_function(client)[0]
        client.event("stopped", predicate=lambda event: event["body"]["reason"] == "exception")
        result = client.request("continue")
        assert result["success"] and not result["body"]["allThreadsContinued"], result
        changed(client, bp["id"])
        stopped(client)
        current = state(client)
        assert current["c"] == 1 and current["held"] == 1, current

    with session("deferred-retained") as client:
        bp = set_function(client)[0]
        changed(client, bp["id"])
        stopped(client)
        refused = client.request("continue", {"threadId": 77, "singleThread": True})
        assert not refused["success"] and "still stopped" in refused["message"], refused
        assert state(client)["held"] == 1
        assert client.request("continue", {"threadId": 77, "singleThread": True})["success"]

    # A dead thread's old exception reason must not hide a reused TID's stop.
    for mode in ("deferred-terminate-old", "deferred-exit-old"):
        with session(mode) as client:
            bp = set_function(client)[0]
            exception = client.event("stopped", predicate=lambda event: event["body"]["reason"] == "exception")
            assert exception["body"]["threadId"] == 88
            if mode == "deferred-terminate-old":
                assert client.request("terminateThreads", {"threadIds": [88]})["success"]
            else:
                assert client.request("readMemory", {"memoryReference": "0x3000", "count": 1})["success"]
                client.event("thread", predicate=lambda event: event["body"]["reason"] == "exited")
            client.event("thread", predicate=lambda event: event["body"]["reason"] == "started")
            changed(client, bp["id"])
            stopped(client, 88)

    for mode in ("deferred-query-error", "deferred-query-short"):
        with session(mode) as client:
            assert not set_function(client)[0]["verified"]
            diagnostic = client.event("output", predicate=lambda event:
                                      "could not be confirmed" in event["body"].get("output", ""))
            assert diagnostic["body"]["category"] == "stderr", diagnostic
            current = state(client)
            assert current["set"] == 0 and current["c"] == 0, current
            no_stop(client)

    with session("deferred-prefix") as client:
        assert not set_function(client)[0]["verified"]
        stopped(client)
        current = state(client)
        assert current["c"] == 0 and current["held"] == 1 and current["set"] == 0, current

    with session("deferred-external") as client:
        set_function(client)
        assert "other.dll" in stopped(client)["body"]["description"]
        assert state(client)["c"] == 0

    for mode in ("deferred-unsupported", "deferred-no-query"):
        with session(mode) as client:
            assert not set_function(client)[0]["verified"]
            assert state(client)["g"] == 0
            no_stop(client)
    print("PASS deferred binding, live-stop reconciliation, explicit resume and reviewed lifecycle cases")


if __name__ == "__main__":
    run()
