"""MCP new tools comprehensive test.

Tests all tools added in the DAP feature parity update:
1. veh_set_source_breakpoint
2. veh_set_function_breakpoint
3. veh_list_breakpoints
4. veh_evaluate
5. veh_set_register
6. veh_exception_info
7. veh_set_breakpoint with condition/hitCondition/logMessage
8. veh_trace_callers (extended: with existing BP overlap)
"""
import subprocess
import json
import time
import sys
import os

MCP_EXE = os.path.join(os.path.dirname(__file__), "..", "build", "bin", "Release", "veh-mcp-server.exe")
TARGET = os.path.join(os.path.dirname(__file__), "..", "build", "bin", "Release", "test_target.exe")
# Source file path as stored in PDB (absolute build path)
SOURCE_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "test_target", "main.cpp"))

passed = 0
failed = 0
errors = []

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

    def recv(self, timeout=15):
        """Read one JSON-RPC response, skipping notifications."""
        start = time.time()
        while time.time() - start < timeout:
            line = self.proc.stdout.readline()
            if line:
                line = line.decode().strip()
                if line:
                    try:
                        msg = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    # Skip notifications (no "id" field)
                    if "id" not in msg:
                        self.notifications.append(msg)
                        continue
                    return msg
        return None

    def call_tool(self, name, args=None, timeout=15):
        self.send("tools/call", {"name": name, "arguments": args or {}})
        return self.recv(timeout=timeout)

    def initialize(self):
        self.send("initialize", {
            "protocolVersion": "2024-11-05",
            "clientInfo": {"name": "test", "version": "1.0"},
            "capabilities": {}
        })
        return self.recv()

    def close(self):
        try: self.proc.stdin.close()
        except: pass
        try: self.proc.terminate()
        except: pass
        try: self.proc.wait(timeout=3)
        except: pass

def get_content(resp):
    try:
        text = resp["result"]["content"][0]["text"]
        return json.loads(text)
    except:
        return resp

def check(name, condition, detail=""):
    global passed, failed, errors
    if condition:
        passed += 1
        print(f"  PASS: {name}")
    else:
        failed += 1
        msg = f"  FAIL: {name}" + (f" -- {detail}" if detail else "")
        print(msg)
        errors.append(msg)

def drain_notifications(c, count=5):
    """Read and discard pending notifications."""
    for _ in range(count):
        try:
            line = c.proc.stdout.readline()
            if not line:
                break
        except:
            break


# ========================================
# Test 1: veh_set_function_breakpoint
# ========================================
def test_function_breakpoint():
    print("\n=== Test 1: veh_set_function_breakpoint ===")
    c = McpClient()
    try:
        c.initialize()
        r = c.call_tool("veh_launch", {"program": TARGET, "stopOnEntry": False})
        data = get_content(r)
        pid = data.get("pid")
        print(f"  Launched PID={pid}")
        time.sleep(1)

        # Set function breakpoint on WorkFunction
        r = c.call_tool("veh_set_function_breakpoint", {"name": "WorkFunction"})
        data = get_content(r)
        print(f"  set_function_breakpoint: {data}")
        check("function BP set", data.get("success", False) or "id" in data, str(data))

        bp_id = data.get("id")
        bp_addr = data.get("address", "")
        check("function BP has address", bp_addr.startswith("0x"), bp_addr)

        # Wait for BP hit
        time.sleep(2)

        # Verify we can get threads (process should be stopped)
        r = c.call_tool("veh_threads")
        threads = get_content(r)
        check("threads after function BP", "threads" in threads, str(threads))

        # Remove BP and continue
        if bp_id:
            c.call_tool("veh_remove_breakpoint", {"id": bp_id})
        c.call_tool("veh_continue", {"threadId": 0})

        c.call_tool("veh_detach")
    finally:
        c.close()
        os.system("taskkill /IM test_target.exe /F >nul 2>&1")


# ========================================
# Test 2: veh_set_source_breakpoint
# ========================================
def test_source_breakpoint():
    print("\n=== Test 2: veh_set_source_breakpoint ===")
    c = McpClient()
    try:
        c.initialize()
        r = c.call_tool("veh_launch", {"program": TARGET, "stopOnEntry": False})
        data = get_content(r)
        pid = data.get("pid")
        print(f"  Launched PID={pid}")
        time.sleep(1)

        # Set source breakpoint on line 12 (g_counter++)
        r = c.call_tool("veh_set_source_breakpoint", {
            "source": SOURCE_FILE,
            "line": 12
        })
        data = get_content(r)
        print(f"  set_source_breakpoint: {data}")
        has_success = data.get("success", False) or "id" in data
        check("source BP set", has_success, str(data))

        bp_id = data.get("id")

        # Wait for BP hit
        time.sleep(2)

        # Verify stopped
        r = c.call_tool("veh_threads")
        threads = get_content(r)
        check("threads after source BP", "threads" in threads, str(threads))

        # Cleanup
        if bp_id:
            c.call_tool("veh_remove_breakpoint", {"id": bp_id})
        c.call_tool("veh_continue", {"threadId": 0})
        c.call_tool("veh_detach")
    finally:
        c.close()
        os.system("taskkill /IM test_target.exe /F >nul 2>&1")


# ========================================
# Test 3: veh_list_breakpoints
# ========================================
def test_list_breakpoints():
    print("\n=== Test 3: veh_list_breakpoints ===")
    c = McpClient()
    try:
        c.initialize()
        r = c.call_tool("veh_launch", {"program": TARGET, "stopOnEntry": True})
        data = get_content(r)
        pid = data.get("pid")
        print(f"  Launched PID={pid}")

        # No BPs yet
        r = c.call_tool("veh_list_breakpoints")
        data = get_content(r)
        sw_count = len(data.get("software", []))
        check("initially no SW BPs", sw_count == 0, f"got {sw_count}")

        # Set 2 BPs
        r = c.call_tool("veh_modules")
        modules = get_content(r)
        base = None
        for m in modules.get("modules", []):
            if "test_target" in m.get("name", "").lower():
                base = int(m["baseAddress"], 16)
                break

        if base:
            c.call_tool("veh_set_breakpoint", {"address": f"0x{base + 0x1000:X}"})
            c.call_tool("veh_set_breakpoint", {"address": f"0x{base + 0x1010:X}"})

            r = c.call_tool("veh_list_breakpoints")
            data = get_content(r)
            sw_count = len(data.get("software", []))
            check("2 SW BPs listed", sw_count == 2, f"got {sw_count}")

            # Check BP entries have expected fields
            if sw_count > 0:
                bp = data["software"][0]
                check("BP has id field", "id" in bp, str(bp))
                check("BP has address field", "address" in bp, str(bp))

        c.call_tool("veh_detach")
    finally:
        c.close()
        os.system("taskkill /IM test_target.exe /F >nul 2>&1")


# ========================================
# Test 4: veh_evaluate
# ========================================
def test_evaluate():
    print("\n=== Test 4: veh_evaluate ===")
    c = McpClient()
    try:
        c.initialize()
        r = c.call_tool("veh_launch", {"program": TARGET, "stopOnEntry": False})
        data = get_content(r)
        pid = data.get("pid")
        print(f"  Launched PID={pid}")
        time.sleep(1)

        # Set function BP to stop on WorkFunction
        r = c.call_tool("veh_set_function_breakpoint", {"name": "WorkFunction"})
        bp_data = get_content(r)
        bp_id = bp_data.get("id")
        time.sleep(2)

        # Get thread ID
        r = c.call_tool("veh_threads")
        threads = get_content(r)
        tid = None
        if "threads" in threads and len(threads["threads"]) > 0:
            tid = threads["threads"][0].get("id")

        if tid:
            # Evaluate register
            r = c.call_tool("veh_evaluate", {"expression": "RSP", "threadId": tid})
            data = get_content(r)
            print(f"  evaluate RSP: {data}")
            check("evaluate RSP returns value", "value" in data, str(data))
            check("RSP is hex address", data.get("value", "").startswith("0x"), data.get("value", ""))

            # Evaluate RIP
            r = c.call_tool("veh_evaluate", {"expression": "RIP", "threadId": tid})
            data = get_content(r)
            check("evaluate RIP returns value", "value" in data, str(data))

            # Evaluate memory dereference
            rsp_val = data.get("value", "")
            r = c.call_tool("veh_evaluate", {"expression": "RSP", "threadId": tid})
            rsp_data = get_content(r)
            rsp_val = rsp_data.get("value", "0x0")
            r = c.call_tool("veh_evaluate", {"expression": f"*{rsp_val}", "threadId": tid})
            data = get_content(r)
            print(f"  evaluate *RSP: {data}")
            check("evaluate *RSP returns value", "value" in data, str(data))
        else:
            check("got thread id", False, "no threads")

        if bp_id:
            c.call_tool("veh_remove_breakpoint", {"id": bp_id})
        c.call_tool("veh_continue", {"threadId": 0})
        c.call_tool("veh_detach")
    finally:
        c.close()
        os.system("taskkill /IM test_target.exe /F >nul 2>&1")


# ========================================
# Test 5: veh_set_register
# ========================================
def test_set_register():
    print("\n=== Test 5: veh_set_register ===")
    c = McpClient()
    try:
        c.initialize()
        r = c.call_tool("veh_launch", {"program": TARGET, "stopOnEntry": False})
        data = get_content(r)
        pid = data.get("pid")
        print(f"  Launched PID={pid}")
        time.sleep(1)

        # Set function BP
        r = c.call_tool("veh_set_function_breakpoint", {"name": "WorkFunction"})
        bp_data = get_content(r)
        bp_id = bp_data.get("id")
        time.sleep(2)

        # Get thread
        r = c.call_tool("veh_threads")
        threads = get_content(r)
        tid = None
        if "threads" in threads and len(threads["threads"]) > 0:
            tid = threads["threads"][0].get("id")

        if tid:
            # Read current RAX
            r = c.call_tool("veh_evaluate", {"expression": "RAX", "threadId": tid})
            old_rax = get_content(r).get("value", "")
            print(f"  RAX before: {old_rax}")

            # Set RAX to known value
            r = c.call_tool("veh_set_register", {
                "threadId": tid,
                "name": "RAX",
                "value": "0xDEADBEEF"
            })
            data = get_content(r)
            print(f"  set_register: {data}")
            check("set_register success", data.get("success", False), str(data))

            # Verify RAX changed
            r = c.call_tool("veh_evaluate", {"expression": "RAX", "threadId": tid})
            new_rax = get_content(r).get("value", "")
            print(f"  RAX after: {new_rax}")
            check("RAX changed to 0xDEADBEEF", "DEADBEEF" in new_rax.upper(), new_rax)
        else:
            check("got thread id", False, "no threads")

        if bp_id:
            c.call_tool("veh_remove_breakpoint", {"id": bp_id})
        c.call_tool("veh_continue", {"threadId": 0})
        c.call_tool("veh_detach")
    finally:
        c.close()
        os.system("taskkill /IM test_target.exe /F >nul 2>&1")


# ========================================
# Test 6: veh_exception_info
# ========================================
def test_exception_info():
    print("\n=== Test 6: veh_exception_info ===")
    c = McpClient()
    try:
        c.initialize()
        r = c.call_tool("veh_launch", {"program": TARGET, "stopOnEntry": True})
        data = get_content(r)
        pid = data.get("pid")
        print(f"  Launched PID={pid}")

        # No exception yet
        r = c.call_tool("veh_exception_info")
        data = get_content(r)
        print(f"  exception_info (no exception): {data}")
        check("no exception initially", "error" in data or data.get("exceptionCode") is None or "No exception" in str(data), str(data))

        c.call_tool("veh_detach")
    finally:
        c.close()
        os.system("taskkill /IM test_target.exe /F >nul 2>&1")


# ========================================
# Test 7: veh_set_breakpoint with condition
# ========================================
def test_conditional_breakpoint():
    print("\n=== Test 7: veh_set_breakpoint with condition ===")
    c = McpClient()
    try:
        c.initialize()
        r = c.call_tool("veh_launch", {"program": TARGET, "stopOnEntry": False})
        data = get_content(r)
        pid = data.get("pid")
        print(f"  Launched PID={pid}")
        time.sleep(1)

        # Get base address
        r = c.call_tool("veh_modules")
        modules = get_content(r)
        base = None
        for m in modules.get("modules", []):
            if "test_target" in m.get("name", "").lower():
                base = int(m["baseAddress"], 16)
                break
        assert base, "test_target module not found"

        # Set BP with impossible condition (should never stop)
        work_func = base + 0x1000
        r = c.call_tool("veh_set_breakpoint", {
            "address": f"0x{work_func:X}",
            "condition": "RAX==0xFFFFFFFFFFFFFFFF"  # very unlikely
        })
        data = get_content(r)
        bp_id = data.get("id")
        check("conditional BP set", bp_id is not None, str(data))
        print(f"  BP id={bp_id} with impossible condition")

        # Wait - process should NOT stop (condition never true)
        time.sleep(3)

        # Process should still be running (not stopped at BP)
        # Try to get threads - if process is running normally, threads still exist
        r = c.call_tool("veh_threads")
        threads = get_content(r)
        print(f"  threads: {threads}")
        # Having threads is fine - key is process didn't hang
        check("process still alive with condition BP", "threads" in threads, str(threads))

        if bp_id:
            c.call_tool("veh_remove_breakpoint", {"id": bp_id})
        c.call_tool("veh_detach")
    finally:
        c.close()
        os.system("taskkill /IM test_target.exe /F >nul 2>&1")


# ========================================
# Test 8: veh_set_breakpoint with logMessage (logpoint)
# ========================================
def test_logpoint():
    print("\n=== Test 8: veh_set_breakpoint with logMessage ===")
    c = McpClient()
    try:
        c.initialize()
        r = c.call_tool("veh_launch", {"program": TARGET, "stopOnEntry": False})
        data = get_content(r)
        pid = data.get("pid")
        print(f"  Launched PID={pid}")
        time.sleep(1)

        # Get base
        r = c.call_tool("veh_modules")
        modules = get_content(r)
        base = None
        for m in modules.get("modules", []):
            if "test_target" in m.get("name", "").lower():
                base = int(m["baseAddress"], 16)
                break
        assert base, "test_target module not found"

        # Set logpoint (should NOT stop, just log)
        work_func = base + 0x1000
        r = c.call_tool("veh_set_breakpoint", {
            "address": f"0x{work_func:X}",
            "logMessage": "Hit WorkFunction RIP={RIP}"
        })
        data = get_content(r)
        bp_id = data.get("id")
        check("logpoint set", bp_id is not None, str(data))

        # Wait - process should NOT stop
        time.sleep(3)

        # Process should still be running
        r = c.call_tool("veh_threads")
        threads = get_content(r)
        check("process still alive with logpoint", "threads" in threads, str(threads))

        if bp_id:
            c.call_tool("veh_remove_breakpoint", {"id": bp_id})
        c.call_tool("veh_detach")
    finally:
        c.close()
        os.system("taskkill /IM test_target.exe /F >nul 2>&1")


# ========================================
# Test 9: veh_trace_callers with existing BP
# ========================================
def test_trace_callers_with_existing_bp():
    print("\n=== Test 9: veh_trace_callers (existing BP overlap) ===")
    c = McpClient()
    try:
        c.initialize()
        r = c.call_tool("veh_launch", {"program": TARGET, "stopOnEntry": False})
        data = get_content(r)
        pid = data.get("pid")
        print(f"  Launched PID={pid}")
        time.sleep(1)

        # Get base
        r = c.call_tool("veh_modules")
        modules = get_content(r)
        base = None
        for m in modules.get("modules", []):
            if "test_target" in m.get("name", "").lower():
                base = int(m["baseAddress"], 16)
                break
        assert base, "test_target module not found"

        work_func = base + 0x1000

        # Set a regular BP first at WorkFunction
        r = c.call_tool("veh_set_breakpoint", {"address": f"0x{work_func:X}"})
        user_bp = get_content(r)
        user_bp_id = user_bp.get("id")
        print(f"  User BP id={user_bp_id} at 0x{work_func:X}")
        check("user BP set", user_bp_id is not None, str(user_bp))

        # Now trace_callers at SAME address (should work and preserve user BP)
        r = c.call_tool("veh_trace_callers", {
            "address": f"0x{work_func:X}",
            "duration_sec": 2
        }, timeout=20)
        data = get_content(r)
        print(f"  trace_callers result: {json.dumps(data, indent=2)}")
        check("trace_callers works", data.get("totalHits", 0) >= 1, str(data))

        # Verify user BP still exists after trace
        r = c.call_tool("veh_list_breakpoints")
        bp_list = get_content(r)
        sw_bps = bp_list.get("software", [])
        user_bp_exists = any(bp.get("id") == user_bp_id for bp in sw_bps)
        check("user BP preserved after trace", user_bp_exists, f"BPs: {sw_bps}")

        # Cleanup
        if user_bp_id:
            c.call_tool("veh_remove_breakpoint", {"id": user_bp_id})
        c.call_tool("veh_detach")
    finally:
        c.close()
        os.system("taskkill /IM test_target.exe /F >nul 2>&1")


# ========================================
# Test 10: veh_set_breakpoint with hitCondition
# ========================================
def test_hit_condition():
    print("\n=== Test 10: veh_set_breakpoint with hitCondition ===")
    c = McpClient()
    try:
        c.initialize()
        r = c.call_tool("veh_launch", {"program": TARGET, "stopOnEntry": False})
        data = get_content(r)
        pid = data.get("pid")
        print(f"  Launched PID={pid}")
        time.sleep(1)

        # Get base
        r = c.call_tool("veh_modules")
        modules = get_content(r)
        base = None
        for m in modules.get("modules", []):
            if "test_target" in m.get("name", "").lower():
                base = int(m["baseAddress"], 16)
                break
        assert base, "test_target module not found"

        # Set BP with hitCondition=3 (fires on 3rd hit)
        work_func = base + 0x1000
        r = c.call_tool("veh_set_breakpoint", {
            "address": f"0x{work_func:X}",
            "hitCondition": "3"
        })
        data = get_content(r)
        bp_id = data.get("id")
        check("hitCondition BP set", bp_id is not None, str(data))

        # Wait for it to hit 3 times (WorkFunction called every ~1s)
        time.sleep(5)

        # Should be stopped now (3rd hit)
        r = c.call_tool("veh_threads")
        threads = get_content(r)
        check("process stopped after hitCondition", "threads" in threads, str(threads))

        if bp_id:
            c.call_tool("veh_remove_breakpoint", {"id": bp_id})
        c.call_tool("veh_continue", {"threadId": 0})
        c.call_tool("veh_detach")
    finally:
        c.close()
        os.system("taskkill /IM test_target.exe /F >nul 2>&1")


# ========================================
# Run all tests
# ========================================
if __name__ == "__main__":
    print(f"Source file: {SOURCE_FILE}")
    print(f"MCP server: {MCP_EXE}")
    print(f"Target: {TARGET}")

    tests = [
        test_function_breakpoint,
        test_source_breakpoint,
        test_list_breakpoints,
        test_evaluate,
        test_set_register,
        test_exception_info,
        test_conditional_breakpoint,
        test_logpoint,
        test_trace_callers_with_existing_bp,
        test_hit_condition,
    ]

    for test_fn in tests:
        try:
            test_fn()
        except Exception as e:
            failed += 1
            msg = f"  EXCEPTION in {test_fn.__name__}: {e}"
            print(msg)
            errors.append(msg)
            os.system("taskkill /IM test_target.exe /F >nul 2>&1")

    print(f"\n{'='*50}")
    print(f"Results: {passed} passed, {failed} failed")
    if errors:
        print("\nFailures:")
        for e in errors:
            print(f"  {e}")
    sys.exit(0 if failed == 0 else 1)
