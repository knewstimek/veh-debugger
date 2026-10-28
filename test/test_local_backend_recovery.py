"""Recover disconnected local agents without weakening a live peer's Detach contract."""
import ctypes
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


def run():
    handles = []
    target = None
    ready = None
    client = OwnedMcpClient()
    with tempfile.TemporaryDirectory(prefix="veh-local-recovery-") as directory:
        try:
            client.initialize()

            def attach(mode="local-recovery", pid=424240):
                result = client.tool("veh_attach", {
                    "pid": pid, "agent": str(FIXTURE), "target_scope": "guest",
                    "agent_args": ["--metadata", mode]})
                assert result.get("success"), result
                agent = int(client.tool("veh_threads")["threads"][0]["name"].split(":")[1])
                handle = owned_handle(agent, FIXTURE, client.proc.pid, directory)
                handles.append(handle)
                return agent, handle

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
            detached = client.tool("veh_detach")
            assert detached.get("success") and "backendCleanupConfirmed" not in detached, detached
            # Never-connect startup must also be captured before an agent PID is exposed.
            failed = client.tool("veh_attach", {"pid": 424240, "agent": str(FIXTURE),
                "target_scope": "guest", "agent_args": ["--metadata", "local-recovery",
                "--pipe", "\\\\.\\pipe\\veh-unconnected-" + suffix]}, timeout=10)
            assert "error" in failed, failed
            print("PASS local death/reconnect, pipe loss, stale cache isolation and failed-startup cleanup")
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
