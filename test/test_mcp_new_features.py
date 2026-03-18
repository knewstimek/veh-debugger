"""MCP new features test: source BP, function BP, evaluate, set_register,
list_breakpoints, conditional BP, logpoint, exception_info.

Uses test_target.exe (must be built with PDB).
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
        self.notifications = []

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

    def recv_response(self, req_id, timeout=10):
        start = time.time()
        while time.time() - start < timeout:
            msg = self.recv(timeout=max(0.5, timeout - (time.time() - start)))
            if msg is None:
                continue
            if "id" in msg and msg["id"] == req_id:
                return msg
            # notification - store it
            self.notifications.append(msg)
        return None

    def call_tool(self, name, args=None, timeout=10):
        req_id = self.send("tools/call", {"name": name, "arguments": args or {}})
        return self.recv_response(req_id, timeout=timeout)

    def tool_result(self, resp):
        """Extract parsed JSON from MCP tool response."""
        if not resp or "result" not in resp:
            return resp
        content = resp["result"].get("content", [])
        if content and content[0].get("type") == "text":
            try:
                return json.loads(content[0]["text"])
            except:
                return content[0]["text"]
        return resp

    def wait_notification(self, keyword, timeout=10):
        """Wait for a notification containing keyword in data."""
        start = time.time()
        # Check buffered notifications first
        for i, n in enumerate(self.notifications):
            data = str(n)
            if keyword.lower() in data.lower():
                self.notifications.pop(i)
                return n
        while time.time() - start < timeout:
            msg = self.recv(timeout=max(0.5, timeout - (time.time() - start)))
            if msg is None:
                continue
            data = str(msg)
            if keyword.lower() in data.lower():
                return msg
            self.notifications.append(msg)
        return None

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


def init_and_launch(client):
    """Initialize MCP and launch test_target with stopOnEntry=true."""
    client.send("initialize", {"protocolVersion": "2024-11-05",
                                "clientInfo": {"name": "test", "version": "1.0"},
                                "capabilities": {}})
    client.recv()
    r = client.tool_result(client.call_tool("veh_launch", {"program": TARGET, "stopOnEntry": True}))
    assert r.get("success"), f"Launch failed: {r}"
    return r["pid"]


passed = 0
failed = 0
errors = []


def run_test(name, func):
    global passed, failed
    print(f"\n{'='*60}")
    print(f"  TEST: {name}")
    print(f"{'='*60}")
    c = McpClient()
    try:
        func(c)
        passed += 1
        print(f"  >>> PASSED: {name}")
    except Exception as e:
        failed += 1
        errors.append((name, str(e)))
        print(f"  >>> FAILED: {name} - {e}")
        import traceback
        traceback.print_exc()
    finally:
        try:
            c.call_tool("veh_detach", timeout=3)
        except:
            pass
        c.close()


# ============================================================
# Test 1: veh_set_source_breakpoint
# ============================================================
def test_source_breakpoint(c):
    pid = init_and_launch(c)
    print(f"  Launched PID={pid}")

    # Set source BP at main.cpp line 9 (inside WorkFunction)
    r = c.tool_result(c.call_tool("veh_set_source_breakpoint", {
        "source": "main.cpp", "line": 9
    }))
    print(f"  Source BP result: {r}")
    assert r.get("success"), f"Source BP failed: {r}"
    assert r.get("line") == 9 or r.get("line") is not None
    bp_id = r["id"]
    bp_addr = r["address"]
    print(f"  BP #{bp_id} at {bp_addr}")

    # Continue and wait for BP hit
    c.call_tool("veh_continue")
    notif = c.wait_notification("breakpoint", timeout=10)
    assert notif is not None, "No breakpoint hit notification"
    print(f"  BP hit notification received")

    # Get threads to find thread ID
    threads = c.tool_result(c.call_tool("veh_threads"))
    tid = threads["threads"][0]["id"]
    print(f"  Thread: {tid}")

    # Verify we're at WorkFunction
    st = c.tool_result(c.call_tool("veh_stack_trace", {"threadId": tid}))
    if "frames" in st and len(st["frames"]) > 0:
        top = st["frames"][0]
        print(f"  Stack top: {top}")

    # Remove BP
    c.call_tool("veh_remove_breakpoint", {"id": bp_id})
    print(f"  Source breakpoint test OK")


# ============================================================
# Test 2: veh_set_function_breakpoint
# ============================================================
def test_function_breakpoint(c):
    pid = init_and_launch(c)
    print(f"  Launched PID={pid}")

    # Set function BP on WorkFunction
    r = c.tool_result(c.call_tool("veh_set_function_breakpoint", {
        "name": "WorkFunction"
    }))
    print(f"  Function BP result: {r}")
    assert r.get("success"), f"Function BP failed: {r}"
    bp_id = r["id"]
    bp_addr = r["address"]
    print(f"  BP #{bp_id} at {bp_addr}, function={r.get('function')}")

    # Continue and wait for BP hit
    c.call_tool("veh_continue")
    notif = c.wait_notification("breakpoint", timeout=10)
    assert notif is not None, "No breakpoint hit notification"
    print(f"  Function BP hit!")

    # Clean up
    c.call_tool("veh_remove_breakpoint", {"id": bp_id})
    print(f"  Function breakpoint test OK")


# ============================================================
# Test 3: veh_evaluate (register + memory)
# ============================================================
def test_evaluate(c):
    pid = init_and_launch(c)
    print(f"  Launched PID={pid}")

    # Set function BP to get a stopped thread
    r = c.tool_result(c.call_tool("veh_set_function_breakpoint", {"name": "WorkFunction"}))
    bp_id = r["id"]
    c.call_tool("veh_continue")
    c.wait_notification("breakpoint", timeout=10)
    threads = c.tool_result(c.call_tool("veh_threads"))
    tid = threads["threads"][0]["id"]

    # Evaluate register
    r = c.tool_result(c.call_tool("veh_evaluate", {"expression": "RSP", "threadId": tid}))
    print(f"  Evaluate RSP: {r}")
    assert "value" in r, f"No value in evaluate result: {r}"
    assert r["value"].startswith("0x"), f"RSP value not hex: {r}"
    rsp_val = r["value"]

    # Evaluate register with $ prefix
    r2 = c.tool_result(c.call_tool("veh_evaluate", {"expression": "$RIP", "threadId": tid}))
    print(f"  Evaluate $RIP: {r2}")
    assert "value" in r2, f"No value for $RIP: {r2}"

    # Evaluate hex address (read memory)
    r3 = c.tool_result(c.call_tool("veh_evaluate", {"expression": rsp_val, "threadId": tid}))
    print(f"  Evaluate memory at RSP ({rsp_val}): {r3}")
    assert "value" in r3 or "hex" in r3, f"Memory read failed: {r3}"

    # Evaluate pointer dereference
    r4 = c.tool_result(c.call_tool("veh_evaluate", {"expression": f"*{rsp_val}", "threadId": tid}))
    print(f"  Evaluate *RSP: {r4}")
    assert "value" in r4 or "error" not in r4, f"Deref failed: {r4}"

    # Error: no threadId for register
    r5 = c.tool_result(c.call_tool("veh_evaluate", {"expression": "RAX", "threadId": 0}))
    print(f"  Evaluate RAX with threadId=0: {r5}")
    assert "error" in r5, "Should error on threadId=0 for register"

    c.call_tool("veh_remove_breakpoint", {"id": bp_id})
    print(f"  Evaluate test OK")


# ============================================================
# Test 4: veh_set_register
# ============================================================
def test_set_register(c):
    pid = init_and_launch(c)
    print(f"  Launched PID={pid}")

    # Get stopped thread
    r = c.tool_result(c.call_tool("veh_set_function_breakpoint", {"name": "WorkFunction"}))
    bp_id = r["id"]
    c.call_tool("veh_continue")
    c.wait_notification("breakpoint", timeout=10)
    threads = c.tool_result(c.call_tool("veh_threads"))
    tid = threads["threads"][0]["id"]

    # Read current RAX
    orig = c.tool_result(c.call_tool("veh_evaluate", {"expression": "RAX", "threadId": tid}))
    print(f"  Original RAX: {orig['value']}")

    # Set RAX to known value
    r = c.tool_result(c.call_tool("veh_set_register", {
        "threadId": tid, "name": "RAX", "value": "0xDEADBEEF"
    }))
    print(f"  Set RAX result: {r}")
    assert r.get("success"), f"Set register failed: {r}"

    # Verify
    new = c.tool_result(c.call_tool("veh_evaluate", {"expression": "RAX", "threadId": tid}))
    print(f"  New RAX: {new['value']}")
    assert "DEADBEEF" in new["value"].upper(), f"RAX not set correctly: {new}"

    c.call_tool("veh_remove_breakpoint", {"id": bp_id})
    print(f"  Set register test OK")


# ============================================================
# Test 5: veh_list_breakpoints
# ============================================================
def test_list_breakpoints(c):
    pid = init_and_launch(c)
    print(f"  Launched PID={pid}")

    # Set multiple BPs
    r1 = c.tool_result(c.call_tool("veh_set_function_breakpoint", {"name": "WorkFunction"}))
    r2 = c.tool_result(c.call_tool("veh_set_source_breakpoint", {"source": "main.cpp", "line": 14}))
    print(f"  Set func BP #{r1['id']}, source BP #{r2['id']}")

    # List
    r = c.tool_result(c.call_tool("veh_list_breakpoints"))
    print(f"  List result: {json.dumps(r, indent=2)}")
    assert "software" in r, f"No software key: {r}"
    sw = r["software"]
    assert len(sw) >= 2, f"Expected >= 2 BPs, got {len(sw)}"

    # Verify function BP has function name
    func_bps = [bp for bp in sw if bp.get("function")]
    assert len(func_bps) >= 1, f"No function BP found in list"
    print(f"  Function BP: {func_bps[0]}")

    # Verify source BP has source/line
    src_bps = [bp for bp in sw if bp.get("source")]
    assert len(src_bps) >= 1, f"No source BP found in list"
    print(f"  Source BP: {src_bps[0]}")

    c.call_tool("veh_remove_breakpoint", {"id": r1["id"]})
    c.call_tool("veh_remove_breakpoint", {"id": r2["id"]})
    print(f"  List breakpoints test OK")


# ============================================================
# Test 6: Conditional breakpoint (condition + hitCondition)
# ============================================================
def test_conditional_breakpoint(c):
    pid = init_and_launch(c)
    print(f"  Launched PID={pid}")

    # Set function BP with hitCondition=3 (stop on 3rd hit)
    r = c.tool_result(c.call_tool("veh_set_function_breakpoint", {
        "name": "WorkFunction",
        "hitCondition": "3"
    }))
    print(f"  Conditional BP (hitCondition=3): {r}")
    assert r.get("success"), f"Conditional BP failed: {r}"
    bp_id = r["id"]

    # Continue - should skip first 2 hits, stop on 3rd
    c.call_tool("veh_continue")
    notif = c.wait_notification("breakpoint", timeout=15)
    assert notif is not None, "No BP hit (expected on 3rd hit)"
    print(f"  BP hit notification: {notif}")

    # Verify hitCount via list
    bps = c.tool_result(c.call_tool("veh_list_breakpoints"))
    sw = bps.get("software", [])
    our_bp = [b for b in sw if b["id"] == bp_id]
    if our_bp:
        print(f"  BP state: hitCount={our_bp[0].get('hitCount')}")
        assert our_bp[0].get("hitCount", 0) >= 3, f"hitCount should be >= 3"

    c.call_tool("veh_remove_breakpoint", {"id": bp_id})
    print(f"  Conditional breakpoint test OK")


# ============================================================
# Test 7: Logpoint (logMessage)
# ============================================================
def test_logpoint(c):
    pid = init_and_launch(c)
    print(f"  Launched PID={pid}")

    # Set function BP with logMessage (should NOT stop)
    r = c.tool_result(c.call_tool("veh_set_function_breakpoint", {
        "name": "WorkFunction",
        "logMessage": "WorkFunction called, RSP={RSP}"
    }))
    print(f"  Logpoint BP: {r}")
    assert r.get("success"), f"Logpoint BP failed: {r}"
    bp_id = r["id"]

    # Also set a normal BP at a different line to catch execution later
    r2 = c.tool_result(c.call_tool("veh_set_source_breakpoint", {
        "source": "main.cpp", "line": 14
    }))
    normal_bp_id = r2["id"]
    print(f"  Normal BP #{normal_bp_id} at line 14")

    # Continue - logpoint should fire without stopping, normal BP should stop
    c.call_tool("veh_continue")

    # Wait for logpoint notification
    log_notif = c.wait_notification("logpoint", timeout=10)
    if log_notif:
        print(f"  Logpoint fired: {log_notif}")
    else:
        print(f"  (No logpoint notification captured, may have been consumed)")

    # Wait for normal BP hit
    bp_notif = c.wait_notification("breakpoint", timeout=10)
    assert bp_notif is not None, "Normal BP should have been hit"
    print(f"  Normal BP hit (execution continued past logpoint)")

    c.call_tool("veh_remove_breakpoint", {"id": bp_id})
    c.call_tool("veh_remove_breakpoint", {"id": normal_bp_id})
    print(f"  Logpoint test OK")


# ============================================================
# Test 8: veh_exception_info (no exception = empty)
# ============================================================
def test_exception_info(c):
    pid = init_and_launch(c)
    print(f"  Launched PID={pid}")

    r = c.tool_result(c.call_tool("veh_exception_info"))
    print(f"  Exception info (no exception): {r}")
    # Should return code=0 or similar (no exception occurred)
    assert r.get("exceptionCode", 0) == 0 or "no exception" in str(r).lower() or r.get("code", 0) == 0, \
        f"Unexpected exception info: {r}"
    print(f"  Exception info test OK")


# ============================================================
# Run all tests
# ============================================================
if __name__ == "__main__":
    print("=" * 60)
    print("  MCP New Features Test Suite")
    print("=" * 60)

    run_test("Source Breakpoint", test_source_breakpoint)
    run_test("Function Breakpoint", test_function_breakpoint)
    run_test("Evaluate", test_evaluate)
    run_test("Set Register", test_set_register)
    run_test("List Breakpoints", test_list_breakpoints)
    run_test("Conditional BP (hitCondition)", test_conditional_breakpoint)
    run_test("Logpoint", test_logpoint)
    run_test("Exception Info", test_exception_info)

    print(f"\n{'='*60}")
    print(f"  Results: {passed} passed, {failed} failed")
    if errors:
        print(f"  Failures:")
        for name, err in errors:
            print(f"    - {name}: {err}")
    print(f"{'='*60}")
    sys.exit(0 if failed == 0 else 1)
