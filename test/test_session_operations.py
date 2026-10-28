"""VM-free execution ownership and leased value-write integration regressions."""
from pathlib import Path
import threading
import time

from build_paths import RELEASE
from owned_mcp_client import OwnedMcpClient

FIXTURE = Path(RELEASE) / "guest_backend_fixture.exe"
PAUSE = threading.Event()


def run():
    with OwnedMcpClient() as client:
        client.initialize("session-operations")

        def tool(name, args=None, timeout=5):
            return client.tool(name, args or {}, timeout=timeout)

        def state(thread=77):
            return tool("veh_execution", {"operation": "state", "threadId": thread})

        def freeze(operation="list", **args):
            return tool("veh_value_freeze", {"operation": operation, **args})

        def attach(mode="normal", *, clear=True):
            result = tool("veh_attach", {"pid": 424242, "agent": str(FIXTURE),
                "target_scope": "guest", "agent_args": ["--metadata", "ops-" + mode]}, timeout=10)
            assert result.get("success"), (mode, result)
            if clear:
                assert freeze("clear").get("success")
            snapshot = state()
            assert isinstance(snapshot.get("sessionGeneration"), str), snapshot
            return snapshot

        def counters():
            result = tool("veh_threads")
            assert result.get("count") == 1, result
            return {key: int(value) for key, value in
                (part.split(":") for part in result["threads"][0]["name"].split())}

        def eventually(read, predicate, message):
            last = None
            for attempt in range(12):
                last = read()
                if predicate(last):
                    return last
                if attempt != 11:
                    PAUSE.wait(0.05)
            raise AssertionError((message, last))

        def finished():
            return eventually(state, lambda result: not result["runUntil"]["active"], "run-until did not retire")

        def run_to(address="0x1800", **args):
            return tool("veh_execution", {"operation": "run_to", "address": address, "threadId": 77, **args})

        def job_by_id(identity):
            jobs = freeze()["jobs"]
            matches = [entry for entry in jobs if entry["id"] == identity]
            assert len(matches) == 1, (identity, jobs)
            return matches[0]

        def add_freeze(**args):
            return freeze("add", address="0x2000", data="AA", lease_seconds=3, **args)

        # State is tri-valued: malformed or refused queries cannot become "running".
        for mode in ("error", "short", "long", "invalid", "unsupported"):
            result = tool("veh_attach", {"pid": 424242, "agent": str(FIXTURE),
                "target_scope": "guest", "agent_args": ["--metadata", "receipt-" + mode]}, timeout=10)
            assert result.get("success"), result
            snapshot = state()
            assert snapshot["state"] == "unknown" and snapshot.get("queryError"), (mode, snapshot)

        # Normal and immediate-before-reply stops both retire exactly the owned BP.
        for mode in ("normal", "fast"):
            before = attach(mode)
            assert before["state"] == "stopped" and not before["runUntil"]["active"], before
            result = run_to()
            assert result.get("success") and result["requestedThreadId"] == 77, result
            assert result["resumeScope"] == "single", result
            snapshot = finished()
            assert snapshot["state"] == "stopped", snapshot
            assert snapshot["lastRunUntil"]["reached"] is True, snapshot
            assert snapshot["lastRunUntil"]["backendCleanupConfirmed"] is True, snapshot
            assert counters() == {"created": 1, "removed": 1, "resumed": 1, "writes": 0}

        # No structured stop traffic without explicit subscription.
        client.call("ping", timeout=3)
        assert not any(n["method"] == "notifications/veh/stopped" for n in client.notifications)
        invalid_subscription = tool("veh_execution", {"operation": "notifications", "enabled": 1})
        assert "error" in invalid_subscription, invalid_subscription
        assert tool("veh_execution", {"operation": "notifications", "enabled": True}).get("success")
        attach("normal")
        assert run_to().get("success")
        finished()
        client.call("ping", timeout=3)
        notices = [n["params"] for n in client.notifications if n["method"] == "notifications/veh/stopped"]
        assert notices and any(n["runUntilReached"] for n in notices), notices
        assert all(isinstance(n["sessionGeneration"], str) and isinstance(n["sequence"], str) for n in notices)
        assert tool("veh_execution", {"operation": "notifications", "enabled": False}).get("success")

        # Borrowed user breakpoint identity survives operation retirement.
        attach("normal")
        installed = tool("veh_set_breakpoint", {"address": "0x1800"})
        assert installed.get("success"), installed
        assert run_to().get("success")
        finished()
        assert counters()["created"] == 1 and counters()["removed"] == 0
        listed = tool("veh_list_breakpoints")
        assert any(bp["id"] == installed["id"] for bp in listed["software"]), listed
        assert tool("veh_remove_breakpoint", {"id": installed["id"]}).get("success")
        assert counters()["removed"] == 1

        # Historical/other-thread stops do not complete the selected thread's new run.
        for mode in ("stale", "other-thread"):
            attach(mode)
            result = run_to()
            assert result.get("success") and result["pending"], result
            snapshot = state()
            assert snapshot["runUntil"]["active"] and snapshot["state"] == "running", snapshot
            assert counters()["removed"] == 0, mode
            assert tool("veh_execution", {"operation": "cancel"}).get("success")
            snapshot = state()
            assert not snapshot["runUntil"]["active"] and snapshot["lastRunUntil"]["reached"] is False
            assert counters()["resumed"] == 1 and counters()["removed"] == 1

        for mode in ("no-create", "no-create-short"):
            attach(mode)
            result = run_to()
            assert "error" in result and "slot" in result["error"], (mode, result)
            assert not state()["runUntil"]["active"] and counters()["created"] == 0
            allowed = tool("veh_write_memory", {"address": "0x2000", "data": "22"})
            assert allowed.get("success"), (mode, "capacity refusal fenced a later mutation", allowed)
        attach("create-ambiguous")
        result = run_to()
        assert "error" in result, result
        snapshot = state()
        assert snapshot["runUntil"]["active"] and snapshot["runUntil"]["uncertain"], snapshot
        assert "error" in run_to("0x1900")
        assert "error" in tool("veh_execution", {"operation": "cancel"})
        # Explicit detach/reattach must remain available despite unknown creation.
        assert tool("veh_detach").get("success")
        assert attach("normal")["state"] == "stopped"

        attach("remove-error")
        assert run_to().get("success")
        result = tool("veh_execution", {"operation": "cancel"})
        assert "error" in result and state()["runUntil"]["uncertain"], result
        assert counters()["removed"] == 1
        state()  # Ordinary state queries do not retry an uncertain removal.
        assert counters()["removed"] == 1
        assert tool("veh_detach").get("success")
        assert not attach("normal")["runUntil"]["active"]

        for mode in ("exit", "drop"):
            old = attach(mode)
            result = run_to()
            assert result.get("success") or "error" in result, result
            eventually(state, lambda result: not result["runUntil"]["active"], "terminal owner still active")
            new = attach("normal")
            assert new["state"] == "stopped" and new["sessionGeneration"] != old["sessionGeneration"], new

        attach("frozen")
        result = run_to()
        assert "error" in result and "frozen" in result["error"], result
        assert counters()["created"] == 0 and counters()["resumed"] == 0
        attach("normal")
        result = tool("veh_step_over", {"threadId": 77})
        assert result.get("success") and result.get("skippedCall"), result
        snapshot = finished()
        assert snapshot["lastRunUntil"]["reached"] is True, snapshot
        assert counters()["created"] == counters()["removed"] == counters()["resumed"] == 1

        attach("normal")
        batch = tool("veh_batch", {"steps": [{"tool": "veh_execution", "args": {
            "operation": "run_to", "address": "0x1800", "threadId": 77}},
            {"tool": "veh_execution", "args": {"operation": "state", "threadId": 77}}]})
        assert batch["failed"] == 0 and batch["results"][0]["result"]["resumeScope"] == "single", batch
        assert finished()["lastRunUntil"]["reached"] is True

        # Required leases, target-width bounds and capability checks precede writes.
        for mode in ("no-read", "no-write"):
            attach(mode)
            result = add_freeze()
            assert "error" in result and counters()["writes"] == 0, (mode, result)
        current = attach("normal")
        bad_arguments = [
            {"address": "0x2000", "data": "AA"},
            {"address": "0x2000", "data": "AA", "lease_seconds": 0},
            {"address": "0x2000", "data": "AA", "lease_seconds": 301},
            {"address": "0x2000", "data": "AA", "lease_seconds": True},
            {"address": "0x2000", "data": "AA", "lease_seconds": 1, "interval_ms": 249},
            {"address": "0x2000", "data": "AA", "lease_seconds": 1, "interval_ms": 60001},
            {"address": "0x2000", "data": "AA" * 65, "lease_seconds": 1},
            {"address": "0x100000000", "data": "AA", "lease_seconds": 1},
            {"address": "0xFFFFFFFF", "data": "AA BB", "lease_seconds": 1},
            {"address": "0x2000", "data": "AZ", "lease_seconds": 1},
            {"address": "0x2000", "data": "AA", "lease_seconds": 1, "expected_generation": "wrong"},
        ]
        report = tool("veh_batch", {"steps": [
            {"tool": "veh_value_freeze", "args": {"operation": "add", **args}} for args in bad_arguments]})
        assert report["failed"] == len(bad_arguments) and freeze()["jobs"] == [], report
        assert counters()["writes"] == 0

        added = add_freeze(expected_generation=current["sessionGeneration"])
        assert added.get("success") and isinstance(added["id"], str), added
        identity = added["id"]
        first = eventually(lambda: job_by_id(identity), lambda job: int(job["writes"]) >= 1, "initial freeze did not write")
        assert first["interval_ms"] == 1000 and first["state"] == "active", first
        assert "error" in run_to(), "run-until overlapped an active freeze"
        assert counters()["created"] == 0
        assert freeze("renew", id=identity, lease_seconds=5).get("success")
        assert job_by_id(identity)["leaseRemainingMs"] > first["leaseRemainingMs"]
        assert "error" in freeze("renew", id=int(identity), lease_seconds=5)
        assert freeze("remove", id=identity).get("success")
        assert freeze()["jobs"] == []

        # Overlap rejection and clear semantics are shared with batch dispatch.
        batch = tool("veh_batch", {"steps": [
            {"tool": "veh_value_freeze", "args": {"operation": "add", "address": "0x2000",
                "data": "AA BB", "lease_seconds": 3, "interval_ms": 60000}},
            {"tool": "veh_value_freeze", "args": {"operation": "add", "address": "0x2001",
                "data": "CC", "lease_seconds": 3}}]})
        assert batch["failed"] == 1 and batch["results"][0]["result"].get("success"), batch
        assert len(freeze()["jobs"]) == 1
        assert freeze("clear").get("success") and freeze()["jobs"] == []

        # The capacity bound is exercised in one bounded batch, not a call per job.
        batch = tool("veh_batch", {"steps": [{"tool": "veh_value_freeze", "args": {
            "operation": "add", "address": hex(0x2000 + index * 4), "data": "11",
            "interval_ms": 60000, "lease_seconds": 3}} for index in range(16)]})
        assert batch["failed"] == 0 and len(freeze()["jobs"]) == 16, batch
        assert "error" in freeze("add", address="0x203F", data="11", lease_seconds=3)
        assert freeze("clear").get("success")

        attach("normal")
        added = freeze("add", address="0x2000", data="AA" * 64, interval_ms=60000, lease_seconds=2)
        assert added.get("success"), added
        eventually(lambda: job_by_id(added["id"]), lambda job: job["writes"] == "1", "64-byte freeze did not finish")
        assert freeze("clear").get("success")

        # Expiry uses a real finite boundary. After expiry no later tick may write.
        attach("normal")
        added = freeze("add", address="0x2000", data="AA", interval_ms=250, lease_seconds=1)
        assert added.get("success"), added
        eventually(lambda: job_by_id(added["id"]), lambda job: int(job["writes"]) >= 1, "expiry first write")
        PAUSE.wait(1.10)
        expired = job_by_id(added["id"])
        assert expired["state"] == "expired" and 1 <= int(expired["writes"]) <= 4, expired
        writes = counters()["writes"]
        assert "error" in freeze("renew", id=added["id"], lease_seconds=1)
        PAUSE.wait(0.28)
        assert counters()["writes"] == writes

        attach("lease-delay")
        added = freeze("add", address="0x2000", data="AA", interval_ms=250, lease_seconds=1)
        assert added.get("success"), added
        expired = eventually(lambda: job_by_id(added["id"]),
            lambda job: job["state"] == "expired", "in-flight expiry did not finish")
        assert expired["writes"] == "1", expired
        PAUSE.wait(0.28)
        assert counters()["writes"] == 1

        # One failed autonomous write/readback fences every active job, with no retries.
        for mode, expected in (("write-error", "write-unconfirmed"), ("write-mismatch", "readback-unconfirmed")):
            attach(mode)
            batch = tool("veh_batch", {"steps": [{"tool": "veh_value_freeze", "args": {
                "operation": "add", "address": hex(0x2000 + index * 16), "data": "AA",
                "interval_ms": 250, "lease_seconds": 2}} for index in range(2)]})
            assert batch["failed"] == 0, batch
            snapshot = eventually(freeze, lambda result: all(job["state"] == expected for job in result["jobs"]),
                                  "uncertain effects did not fence jobs")
            assert len(snapshot["jobs"]) == 2 and counters()["writes"] == 1, snapshot
            PAUSE.wait(0.28)
            assert counters()["writes"] == 1

        # A terminal event admitted during one batch fences a due job before the
        # event loop can acquire the admission lock and submit its first write.
        attach("exit-on-threads")
        report = tool("veh_batch", {"steps": [
            {"tool": "veh_value_freeze", "args": {"operation": "add", "address": "0x2000",
                "data": "AA", "interval_ms": 250, "lease_seconds": 2}},
            {"tool": "veh_threads", "args": {}}]})
        assert report["failed"] == 0, report
        snapshot = freeze()
        assert len(snapshot["jobs"]) == 1 and snapshot["jobs"][0]["state"] != "active", snapshot
        assert counters()["writes"] == 0, "freeze wrote after the target-exit event was admitted"

        # Scope changes preserve terminal job records but never carry active effects.
        old = attach("normal")
        added = add_freeze()
        assert added.get("success"), added
        new = attach("running", clear=False)
        assert new["sessionGeneration"] != old["sessionGeneration"], (old, new)
        assert all(job["state"] != "active" for job in freeze()["jobs"])
        stale = freeze("add", address="0x2000", data="AA", lease_seconds=1,
                       expected_generation=old["sessionGeneration"])
        assert "error" in stale and counters()["writes"] == 0, stale

        attach("drop")
        added = add_freeze()
        assert added.get("success"), added
        eventually(lambda: job_by_id(added["id"]), lambda job: job["writes"] == "1", "initial drop fixture write")
        assert "error" in tool("veh_continue", {"threadId": 77, "wait": False})
        snapshot = freeze()
        assert all(job["state"] != "active" for job in snapshot["jobs"]), snapshot
        attach("normal")

        # Closing the owned control input must stop the autonomous owner promptly.
        added = add_freeze()
        assert added.get("success"), added
        eventually(lambda: job_by_id(added["id"]), lambda job: job["writes"] == "1", "control-loss initial write")
        client.proc.stdin.close()
        client.proc.wait(timeout=5)

    print("PASS execution ownership, lifecycle recovery, notifications and bounded value-freeze direct/batch semantics")


if __name__ == "__main__":
    run()
