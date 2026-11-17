"""Recover disconnected local agents without weakening a live peer's Detach contract."""
import ctypes
import json
import os
from ctypes import wintypes
from pathlib import Path
import subprocess
import tempfile
import uuid

from build_paths import RELEASE
from owned_mcp_client import OwnedMcpClient
from test_remote_transport import KERNEL, owned_handle

FIXTURE = Path(RELEASE) / "guest_backend_fixture.exe"
KERNEL.CreateEventW.argtypes = (ctypes.c_void_p, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR)
KERNEL.CreateEventW.restype = wintypes.HANDLE
KERNEL.OpenThread.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
KERNEL.OpenThread.restype = wintypes.HANDLE
KERNEL.SuspendThread.argtypes = (wintypes.HANDLE,)
KERNEL.SuspendThread.restype = wintypes.DWORD
KERNEL.ResumeThread.argtypes = (wintypes.HANDLE,)
KERNEL.ResumeThread.restype = wintypes.DWORD


def run():
    handles = []
    target = None
    ready = None
    client = OwnedMcpClient()
    with tempfile.TemporaryDirectory(prefix="veh-local-recovery-") as directory:
        try:
            client.initialize()
            # A selected external host backend must never inherit legacy DLL defaults.
            profile = Path(directory) / "backends.json"
            for mode in ("early-exit", "cap-exit", "symbols-unreported", "host-cap", "host-trace"):
                profile.write_text(json.dumps({"hv": {"path": str(FIXTURE.resolve()),
                    "args": ["--metadata", mode]}}), encoding="utf-8")
                probe = OwnedMcpClient(env=dict(os.environ, VEH_BACKENDS=str(profile)))
                try:
                    probe.initialize()
                    result = probe.tool("veh_attach", {"pid": 424242, "backend": "hv"}, timeout=10)
                    if mode in ("host-cap", "host-trace"):
                        assert result.get("success") and result["backend"]["kind"] == "hypervisor", result
                    else:
                        assert "error" in result and not result.get("success"), (mode, result)

                    if result.get("success"):
                        assert probe.tool("veh_detach").get("success")
                    launched = probe.tool("veh_launch", {"program": str(FIXTURE.resolve()),
                        "backend": "hv", "stopOnEntry": True}, timeout=10)
                    if mode in ("host-cap", "host-trace"):
                        assert launched.get("success") and launched["backend"]["kind"] == "hypervisor", launched
                        handle = owned_handle(launched["pid"], FIXTURE, probe.proc.pid, directory)
                        handles.append(handle)
                        traced = probe.tool("veh_trace_callers", {"address": "0x1000", "duration_ms": 50})
                        assert ("error" in traced) == (mode == "host-cap"), traced
                        # Collection, including refusal, must preserve CREATE_SUSPENDED.
                        thread = KERNEL.OpenThread(0x0002, False, launched["mainThreadId"])
                        assert thread, "HV trace ran the suspended target"
                        previous = 0xFFFFFFFF
                        try:
                            previous = KERNEL.SuspendThread(thread)
                            assert previous == 1, ("HV trace changed suspend count", previous)
                        finally:
                            if previous != 0xFFFFFFFF:
                                KERNEL.ResumeThread(thread)  # release only this test's increment
                            KERNEL.CloseHandle(thread)
                        # The completed handshake must retain the owned TERMINATE handle.
                        assert probe.tool("veh_terminate").get("success")
                        assert KERNEL.WaitForSingleObject(handle, 5000) == 0, "owned target survived termination"
                    else:
                        assert "error" in launched and not launched.get("success"), (mode, launched)
                        assert "error" in probe.tool("veh_threads"), "failed launch retained a successful session"
                finally:
                    probe.close(terminate_target=False)

            # One timed-out request fails alone: the session keeps serving other
            # requests and its late reply never answers the next same-command request.
            profile.write_text(json.dumps({"hv": {"path": str(FIXTURE.resolve()),
                "args": ["--metadata", "host-late-reply"]}}), encoding="utf-8")
            probe = OwnedMcpClient(env=dict(os.environ, VEH_BACKENDS=str(profile)))
            try:
                probe.initialize()
                assert probe.tool("veh_attach", {"pid": 424242, "backend": "hv"}, timeout=10).get("success")
                late = probe.tool("veh_pause", {"threadId": 77}, timeout=10)
                assert "timed out" in late.get("error", ""), late
                threads = probe.tool("veh_threads", timeout=10)
                assert threads.get("count") == 1, ("timeout ended the session", threads)
                again = probe.tool("veh_pause", {"threadId": 77}, timeout=10)
                assert again.get("success"), ("late reply blocked or answered the next pause", again)
                detached = probe.tool("veh_detach")
                assert detached.get("success") and "backendCleanupConfirmed" not in detached, detached
            finally:
                probe.close(terminate_target=False)

            def attach(mode="local-recovery", pid=424240, request_log=None):
                arguments = ["--metadata", mode]
                if request_log is not None:
                    arguments += ["--request-log", str(request_log)]
                result = client.tool("veh_attach", {
                    "pid": pid, "agent": str(FIXTURE), "target_scope": "guest",
                    "agent_args": arguments})
                assert result.get("success"), result
                agent = int(client.tool("veh_threads")["threads"][0]["name"].split(":")[1])
                handle = owned_handle(agent, FIXTURE, client.proc.pid, directory)
                handles.append(handle)
                return agent, handle

            # A still-connected runner can outlive its old VM. Ordinary cleanup
            # must retain refusal; only an identity-guarded explicit abandon may retire it.
            for gateway in (False, True):
                audit = Path(directory) / ("abandon-gateway.log" if gateway else "abandon-direct.log")
                old, handle = attach("local-refuse-detach", request_log=audit)
                state = client.tool("veh_execution", {"operation": "state"})
                abandon = {"abandon": True, "expected_session_generation": state["sessionGeneration"],
                           "expected_pid": state["pid"]}
                premature = client.tool("veh_detach", abandon)
                assert "previous failed detach" in premature.get("error", ""), premature
                vm_error = client.tool("veh_virtual_machine", {"operation": "resume"})
                assert vm_error.get("backendStatus") == 1 and "error" in vm_error, vm_error
                vm_batch = client.tool("veh_batch", {"steps": [{"tool": "veh_virtual_machine", "args": {"operation": "resume"}}]})
                assert vm_batch.get("failed", 0) or "error" in vm_batch, vm_batch
                refused = client.tool("veh_detach")
                assert "status 1" in refused.get("error", ""), refused
                blocked = client.tool("veh_attach", {"pid": 424241, "agent": str(FIXTURE),
                    "target_scope": "guest", "agent_args": ["--metadata", "local-recovery"]})
                assert "session retained" in blocked.get("error", ""), blocked
                for invalid in ({}, {"expected_session_generation": "9007199254740993"},
                                {"expected_pid": 424241}, {"expected_session_generation": 1},
                                {"expected_pid": -1}, {"abandon": "true"}):
                    args = dict(abandon, **invalid)
                    if not invalid:
                        args.pop("expected_pid")
                    rejected = client.tool("veh_detach", args)
                    assert "error" in rejected, (args, rejected)
                    assert client.tool("veh_execution", {"operation": "state"})["attached"]
                rejected = client.tool("veh_batch", {"steps": [{"tool": "veh_detach", "args": abandon}]})
                assert rejected.get("failed", 0) or "error" in rejected, rejected
                # No request at all (including Detach/Resume/Terminate) may be added
                # by abandoning. Heartbeats already in flight are the only exception.
                before = audit.read_text().splitlines() if audit.exists() else []
                if gateway:
                    abandoned = client.tool("veh_toolbox", {"operation": "call",
                        "tool": "veh_detach", "arguments": abandon})["result"]
                else:
                    abandoned = client.tool("veh_detach", abandon)
                assert abandoned.get("abandoned") and abandoned["backendCleanupConfirmed"] is False, abandoned
                assert abandoned["previousSession"]["sessionGeneration"] == state["sessionGeneration"]
                assert not client.tool("veh_execution", {"operation": "state"})["attached"]
                after = audit.read_text().splitlines()
                # Heartbeat command is 0x00FE.
                assert [x for x in after if x != "254"] == [x for x in before if x != "254"], (before, after)
                assert KERNEL.WaitForSingleObject(handle, 0) == 258, "abandon terminated the live peer"
                new, _ = attach()
                assert new != old
                stale = client.tool("veh_detach", abandon)
                assert "error" in stale and client.tool("veh_execution", {"operation": "state"})["attached"], stale
                assert client.tool("veh_detach").get("success")
                assert KERNEL.TerminateProcess(handle, 0) and KERNEL.WaitForSingleObject(handle, 5000) == 0

            # A short Ok is not a successful VM control receipt.
            attach("local-control-ok")
            short_ok = client.tool("veh_virtual_machine", {"operation": "resume"})
            assert short_ok.get("error") == "Invalid VM control response" and "state" not in short_ok, short_ok
            assert client.tool("veh_detach").get("success")

            old, handle = attach()
            assert KERNEL.TerminateProcess(handle, 23)
            assert KERNEL.WaitForSingleObject(handle, 5000) == 0
            new, _ = attach()
            assert new != old, "dead cached agent reused"

            # Explicit cleanup must distinguish local recovery from backend acknowledgement.
            old, handle = new, handles[-1]
            assert KERNEL.TerminateProcess(handle, 24)
            assert KERNEL.WaitForSingleObject(handle, 5000) == 0
            detached = client.tool("veh_detach")
            assert detached.get("success") and detached.get("backendCleanupConfirmed") is False, detached
            assert attach()[0] != old
            assert client.tool("veh_detach").get("success")

            # Death while waiting for Detach must not leave an unreplaceable session.
            attach("local-die-detach")
            detached = client.tool("veh_detach")
            assert detached.get("success") and detached.get("backendCleanupConfirmed") is False, detached
            attach()
            assert client.tool("veh_detach").get("success")

            # A pipe can disappear before its agent exits; retire the cache without killing it.
            old, handle = attach("local-drop-live")
            assert "error" in client.tool("veh_threads")
            assert KERNEL.WaitForSingleObject(handle, 0) == 258, "fixture must still be alive"
            new, _ = attach()
            assert new != old and KERNEL.WaitForSingleObject(handle, 0) == 258
            assert client.tool("veh_detach").get("success")

            # A stale external agent for a host PID must not mask the native DLL's Detach.
            suffix = uuid.uuid4().hex
            event_name = "Local\\veh-recovery-" + suffix
            ready = KERNEL.CreateEventW(None, True, False, event_name)
            assert ready
            target = subprocess.Popen([str(FIXTURE), "--pid", "424241",
                "--pipe", "\\\\.\\pipe\\veh-recovery-" + suffix,
                "--metadata", "local-target", "--ready-event", event_name])
            assert KERNEL.WaitForSingleObject(ready, 5000) == 0, "native target readiness"
            _, handle = attach(pid=target.pid)
            assert client.tool("veh_detach").get("success")
            assert KERNEL.WaitForSingleObject(handle, 5000) == 0
            attached = client.tool("veh_attach", {"pid": target.pid})
            assert attached.get("success"), attached
            native_state = client.tool("veh_execution", {"operation": "state"})
            native_abandon = client.tool("veh_detach", {"abandon": True,
                "expected_session_generation": native_state["sessionGeneration"], "expected_pid": native_state["pid"]})
            assert "local external attach" in native_abandon.get("error", ""), native_abandon
            assert client.tool("veh_execution", {"operation": "state"})["attached"]
            detached = client.tool("veh_detach")
            assert detached.get("success") and "backendCleanupConfirmed" not in detached, detached
            # Never-connect startup must also be captured before an agent PID is exposed.
            failed = client.tool("veh_attach", {"pid": 424240, "agent": str(FIXTURE),
                "target_scope": "guest", "agent_args": ["--metadata", "local-recovery",
                "--pipe", "\\\\.\\pipe\\veh-unconnected-" + suffix]}, timeout=10)
            assert "error" in failed, failed
            print("PASS guarded direct/toolbox abandon with no control IPC or peer termination, VM error status, local death/reconnect, pipe loss and native isolation")
        finally:
            client.close(terminate_target=False)
            for handle in handles:
                try:
                    if KERNEL.WaitForSingleObject(handle, 0) == 258:
                        assert KERNEL.TerminateProcess(handle, 0)
                    assert KERNEL.WaitForSingleObject(handle, 5000) == 0
                finally:
                    KERNEL.CloseHandle(handle)
            if target is not None:
                if target.poll() is None:
                    target.terminate()
                target.wait(timeout=5)
            if ready:
                KERNEL.CloseHandle(ready)


if __name__ == "__main__":
    run()
