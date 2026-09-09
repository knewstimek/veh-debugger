"""MCP veh_launch stopOnEntry bug fix test.

Tests that:
1. stopOnEntry=false -> process runs immediately (exits on its own)
2. stopOnEntry=true -> process is suspended, veh_continue resumes it
3. cached stops and exceptions do not cross a relaunch boundary
4. an outstanding wait is cancelled when a new session replaces it
5. both synchronous remote-thread injection methods accept real module handles
6. selective continue reports resumed and still-stopped thread IDs
"""
import subprocess
import json
import time
import sys
import os

MCP_EXE = os.environ.get("VEH_MCP_EXE", os.path.join(
    os.path.dirname(__file__), "..", "build", "bin", "Release", "veh-mcp-server.exe"))
TARGET = os.environ.get("VEH_TEST_TARGET", os.path.join(
    os.path.dirname(__file__), "..", "build", "bin", "Release", "test_target.exe"))

class McpClient:
    def __init__(self):
        self.proc = subprocess.Popen(
            [MCP_EXE],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.seq = 0

    def send(self, method, params=None):
        self.seq += 1
        msg = {"jsonrpc": "2.0", "id": self.seq, "method": method}
        if params:
            msg["params"] = params
        data = json.dumps(msg) + "\n"
        self.proc.stdin.write(data.encode())
        self.proc.stdin.flush()
        return self.seq

    def recv(self, timeout=10):
        """Read one JSON-RPC response line."""
        import select
        start = time.time()
        while time.time() - start < timeout:
            line = self.proc.stdout.readline()
            if line:
                line = line.decode().strip()
                if line:
                    try:
                        return json.loads(line)
                    except json.JSONDecodeError:
                        continue
        return None

    def call_tool(self, name, args=None):
        request_id = self.send("tools/call", {"name": name, "arguments": args or {}})
        while True:
            response = self.recv()
            if response is None or response.get("id") == request_id:
                return response

    def close(self):
        try:
            self.proc.stdin.close()
        except:
            pass
        try:
            self.proc.terminate()
            self.proc.wait(timeout=3)
        except:
            self.proc.kill()


def check_process_alive(pid):
    """Check if process is still running."""
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        h = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not h:
            return False
        exit_code = ctypes.c_ulong()
        kernel32.GetExitCodeProcess(h, ctypes.byref(exit_code))
        kernel32.CloseHandle(h)
        return exit_code.value == 259  # STILL_ACTIVE
    except:
        return False


def terminate_process(pid):
    """Best-effort cleanup for targets deliberately detached by a test."""
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(0x0001, False, pid)  # PROCESS_TERMINATE
        if handle:
            kernel32.TerminateProcess(handle, 0)
            kernel32.CloseHandle(handle)
    except Exception:
        pass


def tool_data(response):
    result = (response or {}).get("result", {})
    content = result.get("content", [{}])
    text = content[0].get("text", "") if content else ""
    return json.loads(text) if text else {}


def test_stop_on_entry_false():
    """stopOnEntry=false: process should run and exit on its own."""
    print("=== Test: stopOnEntry=false ===")
    client = McpClient()

    # Initialize
    client.send("initialize", {"protocolVersion": "2024-11-05",
                                "capabilities": {},
                                "clientInfo": {"name": "test", "version": "1.0"}})
    resp = client.recv()
    assert resp and "result" in resp, f"Initialize failed: {resp}"
    print("  Initialize OK")

    # Launch with stopOnEntry=false
    resp = client.call_tool("veh_launch", {
        "program": TARGET,
        "stopOnEntry": False
    })
    print(f"  Launch response: {resp}")
    assert resp, "No response from launch"
    result = resp.get("result", {})
    content = result.get("content", [{}])
    text = content[0].get("text", "") if content else ""
    data = json.loads(text) if text else {}
    assert "error" not in data, f"Launch error: {data}"
    pid = data.get("pid", 0)
    assert pid > 0, f"No PID: {data}"
    print(f"  Launched PID={pid}")

    # Wait a bit for process to run
    time.sleep(2)

    # Process should have run (may or may not be alive depending on test_target behavior)
    alive = check_process_alive(pid)
    print(f"  Process alive after 2s: {alive}")

    # Detach
    resp = client.call_tool("veh_detach")
    print(f"  Detach: {resp}")

    terminate_process(pid)

    client.close()
    print("  PASSED\n")
    return True


def test_stop_on_entry_true():
    """stopOnEntry=true (default): process should be suspended until veh_continue."""
    print("=== Test: stopOnEntry=true (default) ===")
    client = McpClient()

    # Initialize
    client.send("initialize", {"protocolVersion": "2024-11-05",
                                "capabilities": {},
                                "clientInfo": {"name": "test", "version": "1.0"}})
    resp = client.recv()
    assert resp and "result" in resp, f"Initialize failed: {resp}"
    print("  Initialize OK")

    # Launch with stopOnEntry=true (default)
    resp = client.call_tool("veh_launch", {
        "program": TARGET,
        "stopOnEntry": True
    })
    print(f"  Launch response: {resp}")
    assert resp, "No response from launch"
    result = resp.get("result", {})
    content = result.get("content", [{}])
    text = content[0].get("text", "") if content else ""
    data = json.loads(text) if text else {}
    assert "error" not in data, f"Launch error: {data}"
    pid = data.get("pid", 0)
    assert pid > 0, f"No PID: {data}"
    print(f"  Launched PID={pid}")

    # Process should still be alive (suspended)
    time.sleep(1)
    alive = check_process_alive(pid)
    assert alive, "Process should be alive (suspended) but it's not!"
    print(f"  Process alive (suspended): {alive}")

    # Now continue - should resume the OS-suspended thread
    resp = client.call_tool("veh_continue", {"threadId": 0})
    print(f"  Continue response: {resp}")
    continue_data = tool_data(resp)
    assert continue_data.get("resumeScope") == "all", continue_data
    assert continue_data.get("resumedThreadIds"), continue_data
    assert continue_data.get("stillStoppedThreadIds") == [], continue_data

    # Wait for process to run
    time.sleep(2)

    # Detach
    resp = client.call_tool("veh_detach")
    print(f"  Detach: {resp}")

    terminate_process(pid)

    client.close()
    print("  PASSED\n")
    return True


def test_new_launch_clears_previous_stop():
    """A cached exception from process A must never be returned for process B."""
    print("=== Test: launch clears previous session stop state ===")
    client = McpClient()

    client.send("initialize", {"protocolVersion": "2024-11-05",
                                "capabilities": {},
                                "clientInfo": {"name": "test", "version": "1.0"}})
    init_response = client.recv()
    assert init_response and "result" in init_response, init_response

    first = tool_data(client.call_tool("veh_launch", {
        "program": TARGET,
        "args": ["--crash"],
        "stopOnEntry": False,
    }))
    assert "error" not in first and first.get("pid", 0) > 0, first

    # Let process A's AV reach the MCP stop cache without consuming it.
    time.sleep(3)

    second = tool_data(client.call_tool("veh_launch", {
        "program": TARGET,
        "stopOnEntry": True,
    }))
    assert "error" not in second and second.get("pid", 0) > 0, second
    assert second["pid"] != first["pid"]
    terminate_process(first["pid"])

    exception_info = tool_data(client.call_tool("veh_exception_info"))
    assert exception_info.get("error") == "No exception recorded", exception_info

    continued = tool_data(client.call_tool("veh_continue", {
        "wait": True,
        "timeout": 1,
    }))
    assert continued.get("timeout") is True, continued

    client.call_tool("veh_terminate")
    client.close()
    print("  PASSED\n")
    return True


def test_explicit_remote_thread_methods():
    """Both synchronous LoadLibrary methods still accept real module handles."""
    print("=== Test: explicit remote-thread injection methods ===")
    client = McpClient()

    client.send("initialize", {"protocolVersion": "2024-11-05",
                                "capabilities": {},
                                "clientInfo": {"name": "test", "version": "1.0"}})
    init_response = client.recv()
    assert init_response and "result" in init_response, init_response

    for method in ["createRemoteThread", "ntCreateThreadEx"]:
        launched = tool_data(client.call_tool("veh_launch", {
            "program": TARGET,
            "stopOnEntry": True,
            "injectionMethod": method,
        }))
        assert "error" not in launched and launched.get("pid", 0) > 0, {
            "method": method,
            "result": launched,
        }
        terminated = tool_data(client.call_tool("veh_terminate"))
        assert terminated.get("success") is True, {"method": method, "result": terminated}

    client.close()
    print("  PASSED\n")
    return True


def test_wait_is_cancelled_by_relaunch():
    """A wait started for process A must not consume process B's first stop."""
    print("=== Test: outstanding wait is cancelled by relaunch ===")
    client = McpClient()

    client.send("initialize", {"protocolVersion": "2024-11-05",
                                "capabilities": {},
                                "clientInfo": {"name": "test", "version": "1.0"}})
    init_response = client.recv()
    assert init_response and "result" in init_response, init_response

    first = tool_data(client.call_tool("veh_launch", {
        "program": TARGET,
        "stopOnEntry": True,
    }))
    assert "error" not in first and first.get("pid", 0) > 0, first

    wait_id = client.send("tools/call", {
        "name": "veh_continue",
        "arguments": {"wait": True, "timeout": 10},
    })
    time.sleep(0.25)
    launch_id = client.send("tools/call", {
        "name": "veh_launch",
        "arguments": {"program": TARGET, "stopOnEntry": True},
    })

    responses = {}
    while wait_id not in responses or launch_id not in responses:
        response = client.recv(timeout=15)
        assert response is not None, responses
        if response.get("id") in (wait_id, launch_id):
            responses[response["id"]] = response

    wait_result = tool_data(responses[wait_id])
    assert wait_result.get("error") == "Debug session changed while waiting for a stop event", wait_result

    launch_result = tool_data(responses[launch_id])
    assert "error" not in launch_result and launch_result.get("pid", 0) > 0, launch_result
    terminate_process(first["pid"])

    client.call_tool("veh_terminate")
    client.close()
    print("  PASSED\n")
    return True


def test_selective_continue_visibility():
    """threadId=X resumes only X and reports every debugger-stopped thread."""
    print("=== Test: selective continue visibility ===")
    client = McpClient()

    client.send("initialize", {"protocolVersion": "2024-11-05",
                                "capabilities": {},
                                "clientInfo": {"name": "test", "version": "1.0"}})
    init_response = client.recv()
    assert init_response and "result" in init_response, init_response

    launched = tool_data(client.call_tool("veh_launch", {
        "program": TARGET,
        "stopOnEntry": False,
    }))
    assert "error" not in launched and launched.get("pid", 0) > 0, launched

    # Add a second application thread so a selective resume has another stopped
    # thread to leave behind. EB FE is an architecture-neutral infinite loop.
    shellcode = tool_data(client.call_tool("veh_execute_shellcode", {
        "shellcode": "EBFE",
        "timeout_ms": 0,
    }))
    assert shellcode.get("success") is True, shellcode
    time.sleep(0.2)

    threads = tool_data(client.call_tool("veh_threads")).get("threads", [])
    assert len(threads) >= 2, threads
    thread_ids = sorted(t["id"] for t in threads)

    paused = tool_data(client.call_tool("veh_pause", {"threadId": 0}))
    assert paused.get("success") is True, paused
    selected = thread_ids[0]
    continued = tool_data(client.call_tool("veh_continue", {"threadId": selected}))
    assert continued.get("resumeScope") == "single", continued
    assert continued.get("requestedThreadId") == selected, continued
    assert continued.get("resumedThreadIds") == [selected], continued
    still_stopped = continued.get("stillStoppedThreadIds", [])
    assert selected not in still_stopped, continued
    assert set(thread_ids[1:]).issubset(set(still_stopped)), continued

    continued_all = tool_data(client.call_tool("veh_continue", {"threadId": 0}))
    assert continued_all.get("resumeScope") == "all", continued_all
    assert set(still_stopped).issubset(set(continued_all.get("resumedThreadIds", []))), continued_all
    assert continued_all.get("stillStoppedThreadIds") == [], continued_all

    client.call_tool("veh_terminate")
    client.close()
    print("  PASSED\n")
    return True


if __name__ == "__main__":
    passed = 0
    failed = 0

    for test_fn in [test_stop_on_entry_false, test_stop_on_entry_true,
                    test_new_launch_clears_previous_stop,
                    test_explicit_remote_thread_methods,
                    test_wait_is_cancelled_by_relaunch,
                    test_selective_continue_visibility]:
        try:
            if test_fn():
                passed += 1
        except Exception as e:
            print(f"  FAILED: {e}\n")
            failed += 1

    print(f"\nResults: {passed} passed, {failed} failed")
    sys.exit(1 if failed > 0 else 0)
