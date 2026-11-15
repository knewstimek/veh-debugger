"""DAP guest attachment validates its IPC peer and never uses host PID APIs."""
from pathlib import Path

from build_paths import RELEASE
from dap_test_client import DapClient


ADAPTER = str(Path(RELEASE) / "veh-debug-adapter.exe")
AGENT = str(Path(RELEASE) / "guest_backend_fixture.exe")
PID = 4242


def attach(mode="guest"):
    client = DapClient(ADAPTER)
    client.initialize()
    response = client.request("attach", {
        "targetScope": "guest",
        "processId": PID,
        "agent": AGENT,
        "agentArgs": ["--metadata", mode],
    }, timeout=10)
    return client, response


def run():
    client, response = attach()
    try:
        assert response["success"], response
        assert client.request("configurationDone")["success"]
        threads = client.request("threads")
        assert threads["success"] and threads["body"]["threads"][0]["id"] == 77, threads
        memory = client.request("readMemory", {"memoryReference": "0x1000", "count": 2})
        assert memory["success"] and memory["body"]["data"] == "QsM=", memory
        disassembly = client.request("disassemble", {
            "memoryReference": "0x1000", "instructionCount": 1,
        })
        assert disassembly["success"] and disassembly["body"]["instructions"], disassembly
        for arguments in (
            {"memoryReference": "0xffffffff", "count": 2},
            {"memoryReference": "0x0", "offset": -1, "count": 2},
            {"memoryReference": "0xffffffffffffffff", "count": 2},
        ):
            rejected = client.request("readMemory", arguments)
            assert not rejected["success"] and "outside" in rejected["message"], rejected
        rejected = client.request("disassemble", {
            "memoryReference": "0xffffffff", "instructionCount": 1,
        })
        assert not rejected["success"] and "outside" in rejected["message"], rejected
        for command in ("modules", "pause", "terminate", "launch"):
            rejected = client.request(command)
            assert not rejected["success"] and "not supported" in rejected["message"], rejected
        rejected = client.request("disconnect", {"terminateDebuggee": True})
        assert not rejected["success"] and "not supported" in rejected["message"], rejected
        assert client.request("disconnect", {"terminateDebuggee": False})["success"]
        exit_code = client.proc.wait(timeout=3)
        assert exit_code == 0, (exit_code, client.stderr_tail())
    finally:
        client.close(terminate_debuggee=False)

    client, response = attach("detach-three-errors")
    try:
        assert response["success"], response
        for _ in range(3):
            failed = client.request("disconnect", {"terminateDebuggee": False})
            assert not failed["success"] and "retained" in failed["message"], failed
            threads = client.request("threads")
            assert threads["success"] and len(threads["body"]["threads"]) == 1, threads
        assert client.request("disconnect", {"terminateDebuggee": False})["success"]
        exit_code = client.proc.wait(timeout=3)
        assert exit_code == 0, (exit_code, client.stderr_tail())
    finally:
        client.close(terminate_debuggee=False)

    # A guest Terminate answered with Error is not an exit: no success, no terminated event.
    client, response = attach("fail-reason")
    try:
        assert response["success"], response
        failed = client.request("terminate")
        assert not failed["success"] and "not confirmed" in failed["message"], failed
        threads = client.request("threads")
        assert threads["success"] and len(threads["body"]["threads"]) == 1, threads
        assert client.request("disconnect", {"terminateDebuggee": False})["success"]
        exit_code = client.proc.wait(timeout=3)
        assert exit_code == 0, (exit_code, client.stderr_tail())
    finally:
        client.close(terminate_debuggee=False)

    for mode in ("wrong-pid", "bad-width", "wrong-scope", "truncated", "host-cap"):
        client, response = attach(mode)
        try:
            assert not response["success"], (mode, response)
            assert response["message"], response
        finally:
            client.close(terminate_debuggee=False)

    client = DapClient(ADAPTER)
    try:
        client.initialize()
        for arguments in (
            {"targetScope": "host", "processId": PID, "agent": AGENT},
            {"targetScope": "guest", "processId": PID, "agent": "Z:\\\\missing.exe"},
            {"targetScope": "guest", "processId": 0, "agent": AGENT},
        ):
            response = client.request("attach", arguments)
            assert not response["success"], response
    finally:
        client.close(terminate_debuggee=False)
    print("PASS DAP external guest attach, read-only IPC, scope validation and failure paths")


if __name__ == "__main__":
    run()
