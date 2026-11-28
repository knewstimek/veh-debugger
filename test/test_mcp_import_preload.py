"""veh_launch injectionMethod=importTable on the synthetic preload_host fixture.

1. The payload initializes before the host's static DLL; remote-thread launch does not.
2. stopOnEntry keeps the main thread suspended until veh_continue.
3. restoreImports puts the original import directory back; without it the patch stays.
4. restoreImports without importTable is rejected before any process starts.

VEH_MCP_EXE selects another server, e.g. the x64 server against the build32 host (WoW64).
"""
import os
import sys
import tempfile
import time

from build_paths import RELEASE
from dap_test_client import DapClient
from mcp_test_client import McpClient

HOST = os.path.join(RELEASE, "preload_host.exe")
ADAPTER = os.path.join(RELEASE, "veh-debug-adapter.exe")


def wait_report(path, pid_alive, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if os.path.exists(path):
            with open(path, encoding="ascii") as report:
                return dict(item.split("=") for item in report.read().split())
        if not pid_alive():
            raise AssertionError("preload_host exited without a report")
        time.sleep(0.05)
    raise AssertionError("preload_host report timed out")


def process_alive(pid):
    import ctypes
    kernel32 = ctypes.windll.kernel32
    handle = kernel32.OpenProcess(0x1000, False, pid)
    if not handle:
        return False
    code = ctypes.c_ulong()
    kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
    kernel32.CloseHandle(handle)
    return code.value == 259


def run_case(client, workdir, name, arguments):
    report = os.path.join(workdir, name + ".txt")
    launched = client.tool("veh_launch", {"program": HOST, "args": [report], "stopOnEntry": True, **arguments},
                           timeout=90)
    assert "error" not in launched and launched.get("pid", 0) > 0, (name, launched)
    pid = launched["pid"]
    try:
        assert process_alive(pid) and not os.path.exists(report), (name, "main thread ran before continue")
        continued = client.tool("veh_continue", {"threadId": 0})
        assert continued.get("resumedThreadIds"), (name, continued)
        return wait_report(report, lambda: process_alive(pid))
    finally:
        client.tool("veh_terminate", timeout=10)


def run_dap(adapter):
    """DAP launch parity: same option names, resume on configurationDone."""
    with tempfile.TemporaryDirectory(prefix="veh-import-preload-dap-") as workdir:
        client = DapClient(adapter)
        try:
            client.initialize()
            rejected = client.request("launch", {"program": HOST, "args": [os.path.join(workdir, "never.txt")],
                                                 "restoreImports": True})
            assert not rejected.get("success") and "importTable" in rejected.get("message", ""), rejected
            report = os.path.join(workdir, "dap.txt")
            launched = client.request("launch", {"program": HOST, "args": [report], "injectionMethod": "importTable",
                                                 "restoreImports": True}, timeout=90)
            assert launched.get("success"), launched
            assert not os.path.exists(report), "main thread ran before configurationDone"
            done = client.request("configurationDone")
            assert done.get("success"), done
            deadline = time.monotonic() + 15
            while not os.path.exists(report):
                assert time.monotonic() < deadline, "DAP preload_host report timed out"
                time.sleep(0.05)
            with open(report, encoding="ascii") as handle:
                assert handle.read().split() == ["first=1", "restored=1"]
        finally:
            client.close()


def main():
    assert os.path.exists(HOST), f"build preload_host first: {HOST}"
    with tempfile.TemporaryDirectory(prefix="veh-import-preload-") as workdir, McpClient(os.environ.get("VEH_MCP_EXE")) as client:
        client.initialize()

        legacy = run_case(client, workdir, "legacy", {"injectionMethod": "createRemoteThread"})
        assert legacy == {"first": "0", "restored": "1"}, legacy

        kept = run_case(client, workdir, "kept", {"injectionMethod": "importTable"})
        assert kept == {"first": "1", "restored": "0"}, kept

        restored = run_case(client, workdir, "restored", {"injectionMethod": "importTable", "restoreImports": True})
        assert restored == {"first": "1", "restored": "1"}, restored

        rejected = client.tool("veh_launch", {"program": HOST, "args": [os.path.join(workdir, "never.txt")],
                                              "restoreImports": True})
        assert "restoreImports requires injectionMethod=importTable" in rejected.get("error", ""), rejected
        assert not os.path.exists(os.path.join(workdir, "never.txt"))

    if os.path.exists(ADAPTER):
        run_dap(ADAPTER)
    print("PASS test_mcp_import_preload")
    return 0


if __name__ == "__main__":
    sys.exit(main())
