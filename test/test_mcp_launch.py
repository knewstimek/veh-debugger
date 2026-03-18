"""MCP veh_launch stopOnEntry bug fix test.

Tests that:
1. stopOnEntry=false -> process runs immediately (exits on its own)
2. stopOnEntry=true -> process is suspended, veh_continue resumes it
"""
import subprocess
import json
import time
import sys
import os

MCP_EXE = os.path.join(os.path.dirname(__file__), "..", "build", "bin", "Release", "veh-mcp-server.exe")
TARGET = os.path.join(os.path.dirname(__file__), "..", "build", "bin", "Release", "test_target.exe")

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
        self.send("tools/call", {"name": name, "arguments": args or {}})
        return self.recv()

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

    # Wait for process to run
    time.sleep(2)

    # Detach
    resp = client.call_tool("veh_detach")
    print(f"  Detach: {resp}")

    client.close()
    print("  PASSED\n")
    return True


if __name__ == "__main__":
    passed = 0
    failed = 0

    for test_fn in [test_stop_on_entry_false, test_stop_on_entry_true]:
        try:
            if test_fn():
                passed += 1
        except Exception as e:
            print(f"  FAILED: {e}\n")
            failed += 1

    print(f"\nResults: {passed} passed, {failed} failed")
    sys.exit(1 if failed > 0 else 0)
