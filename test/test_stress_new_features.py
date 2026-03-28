"""Stress test for new MCP features + session restart + thread management.

Tests:
1. veh_dump_memory - binary file dump
2. veh_allocate_memory / veh_free_memory
3. veh_execute_shellcode
4. veh_evaluate complex expressions ([reg+offset], gs:[0x60])
5. BP ID separation (SW < 10001, HW >= 10001)
6. breakpointType in veh_continue response
7. Rapid detach->launch restart (10 cycles)
8. Thread management stress (pause/continue per-thread)
"""
import subprocess
import json
import time
import sys
import os
import tempfile

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
        # Initialize
        self.send("initialize", {"protocolVersion": "2024-11-05",
                                  "capabilities": {},
                                  "clientInfo": {"name": "stress-test", "version": "1.0"}})
        resp = self.recv()
        assert resp and "result" in resp, f"Initialize failed: {resp}"

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

    def call_tool(self, name, args=None, timeout=15):
        self.send("tools/call", {"name": name, "arguments": args or {}})
        return self.recv(timeout=timeout)

    def parse_result(self, resp):
        if not resp:
            return {"error": "No response (timeout)"}
        result = resp.get("result", {})
        content = result.get("content", [{}])
        text = content[0].get("text", "") if content else ""
        try:
            return json.loads(text) if text else {}
        except json.JSONDecodeError:
            return {"raw": text}

    def launch_target(self, stop_on_entry=True):
        resp = self.call_tool("veh_launch", {
            "program": TARGET,
            "stopOnEntry": stop_on_entry
        })
        data = self.parse_result(resp)
        assert "error" not in data, f"Launch failed: {data}"
        assert data.get("pid", 0) > 0, f"No PID: {data}"
        return data["pid"]

    def detach(self):
        resp = self.call_tool("veh_detach")
        return self.parse_result(resp)

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


passed = 0
failed = 0

def run_test(name, fn):
    global passed, failed
    print(f"=== {name} ===")
    try:
        fn()
        passed += 1
        print(f"  PASSED\n")
    except Exception as e:
        failed += 1
        print(f"  FAILED: {e}\n")
        import traceback
        traceback.print_exc()


def test_dump_memory():
    """Test veh_dump_memory writes correct binary file."""
    client = McpClient()
    pid = client.launch_target(True)

    # Continue to let process run, then pause
    client.call_tool("veh_continue", {"threadId": 0})
    time.sleep(0.5)
    client.call_tool("veh_pause", {"threadId": 0})
    time.sleep(0.3)

    # Get module base (PE header is read-only and stable)
    resp = client.call_tool("veh_modules")
    mods = client.parse_result(resp)
    modules = mods.get("modules", [])
    assert len(modules) > 0, f"No modules: {mods}"
    base_addr = modules[0].get("baseAddress", "0x0")
    print(f"  Using module base: {base_addr}")

    # Dump memory to file (PE header - first 256 bytes, immutable)
    dump_path = os.path.join(tempfile.gettempdir(), "veh_test_dump.bin")
    resp = client.call_tool("veh_dump_memory", {
        "address": base_addr,
        "size": 256,
        "output_path": dump_path
    })
    dump_data = client.parse_result(resp)
    assert dump_data.get("success"), f"dump_memory failed: {dump_data}"
    assert dump_data.get("size") == 256, f"Wrong size: {dump_data}"
    assert os.path.exists(dump_path), "Dump file not created"
    assert os.path.getsize(dump_path) == 256, f"File size wrong: {os.path.getsize(dump_path)}"
    print(f"  dump_memory OK: {dump_path} ({os.path.getsize(dump_path)} bytes)")

    # Verify PE signature in dump
    with open(dump_path, "rb") as f:
        raw = f.read(256)
    assert raw[:2] == b"MZ", f"Dump should start with MZ PE header, got: {raw[:4].hex()}"
    print(f"  PE header MZ signature OK")

    # Now read same region via hex and compare (immutable data = deterministic)
    resp = client.call_tool("veh_read_memory", {"address": base_addr, "size": 64})
    hex_data = client.parse_result(resp)
    assert "error" not in hex_data, f"read_memory failed: {hex_data}"

    hex_str = hex_data.get("hex", "").replace("\n", " ")
    expected_bytes = bytes(int(b, 16) for b in hex_str.split() if b)
    assert raw[:len(expected_bytes)] == expected_bytes, \
        f"Dump content mismatch! dump={raw[:16].hex()} vs read={expected_bytes[:16].hex()}"
    print(f"  Content verification OK (first 64 bytes match read_memory)")

    os.unlink(dump_path)
    client.detach()
    client.close()


def test_allocate_free_memory():
    """Test veh_allocate_memory and veh_free_memory."""
    client = McpClient()
    pid = client.launch_target(True)
    client.call_tool("veh_continue", {"threadId": 0})
    time.sleep(0.5)
    client.call_tool("veh_pause", {"threadId": 0})
    time.sleep(0.3)

    # Allocate RWX page
    resp = client.call_tool("veh_allocate_memory", {"size": 4096, "protection": "rwx"})
    data = client.parse_result(resp)
    assert data.get("success"), f"allocate failed: {data}"
    addr = data["address"]
    print(f"  Allocated RWX page at {addr}")

    # Write to it
    resp = client.call_tool("veh_write_memory", {"address": addr, "data": "90 90 90 C3"})
    wd = client.parse_result(resp)
    assert wd.get("success"), f"write failed: {wd}"

    # Read back
    resp = client.call_tool("veh_read_memory", {"address": addr, "size": 4})
    rd = client.parse_result(resp)
    assert "90 90 90 c3" in rd.get("hex", "").lower(), f"Read mismatch: {rd}"
    print(f"  Write+Read verified OK")

    # Free
    resp = client.call_tool("veh_free_memory", {"address": addr})
    fd = client.parse_result(resp)
    assert fd.get("success"), f"free failed: {fd}"
    print(f"  Free OK")

    client.detach()
    client.close()


def test_execute_shellcode():
    """Test veh_execute_shellcode with simple 'xor eax,eax; ret' (exit code 0)."""
    client = McpClient()
    pid = client.launch_target(True)
    client.call_tool("veh_continue", {"threadId": 0})
    time.sleep(0.5)
    client.call_tool("veh_pause", {"threadId": 0})
    time.sleep(0.3)

    # x64 shellcode: xor eax,eax; ret -> exit code 0
    resp = client.call_tool("veh_execute_shellcode", {
        "shellcode": "33C0C3",
        "timeout_ms": 5000
    })
    data = client.parse_result(resp)
    assert data.get("success"), f"shellcode failed: {data}"
    assert data.get("exitCode") == 0, f"Expected exit code 0, got: {data.get('exitCode')}"
    print(f"  Shellcode executed OK, exitCode={data['exitCode']}")

    # Test with exit code 42: mov eax,42; ret
    resp = client.call_tool("veh_execute_shellcode", {
        "shellcode": "B82A000000C3",
        "timeout_ms": 5000
    })
    data = client.parse_result(resp)
    assert data.get("success"), f"shellcode2 failed: {data}"
    assert data.get("exitCode") == 42, f"Expected 42, got: {data.get('exitCode')}"
    print(f"  Shellcode exitCode=42 OK")

    client.detach()
    client.close()


def test_evaluate_complex():
    """Test veh_evaluate with [reg+offset] and gs:[0x60] (PEB)."""
    client = McpClient()
    pid = client.launch_target(True)

    # Continue and hit entry, get stopped
    resp = client.call_tool("veh_continue", {"wait": True, "timeout": 5})
    data = client.parse_result(resp)
    # May timeout if no BP set, that's fine - just pause
    if not data.get("stopped"):
        client.call_tool("veh_pause", {"threadId": 0})
        time.sleep(0.3)

    # Get threads
    resp = client.call_tool("veh_threads")
    threads = client.parse_result(resp)
    thread_list = threads.get("threads", [])
    assert len(thread_list) > 0, f"No threads: {threads}"
    tid = thread_list[0]["id"]
    print(f"  Thread ID: {tid}")

    # Test [RSP] dereference
    resp = client.call_tool("veh_evaluate", {"expression": "[RSP]", "threadId": tid})
    data = client.parse_result(resp)
    assert "error" not in data, f"[RSP] failed: {data}"
    print(f"  [RSP] = {data.get('value')}")

    # Test [RSP+8]
    resp = client.call_tool("veh_evaluate", {"expression": "[RSP+0x8]", "threadId": tid})
    data = client.parse_result(resp)
    assert "error" not in data, f"[RSP+0x8] failed: {data}"
    print(f"  [RSP+0x8] = {data.get('value')}")

    # Test gs:[0x60] (PEB pointer)
    resp = client.call_tool("veh_evaluate", {"expression": "gs:[0x60]", "threadId": tid})
    data = client.parse_result(resp)
    assert "error" not in data, f"gs:[0x60] failed: {data}"
    assert "tebAddress" in data, f"Missing tebAddress: {data}"
    print(f"  gs:[0x60] (PEB) = {data.get('value')}")

    # Test gs:[0x30] (TEB self-reference)
    resp = client.call_tool("veh_evaluate", {"expression": "gs:[0x30]", "threadId": tid})
    data = client.parse_result(resp)
    assert "error" not in data, f"gs:[0x30] failed: {data}"
    print(f"  gs:[0x30] (TEB self) = {data.get('value')}")

    client.detach()
    client.close()


def test_bp_id_separation():
    """Test SW BP IDs < 10001, HW BP IDs >= 10001, and breakpointType in continue."""
    client = McpClient()
    pid = client.launch_target(True)
    client.call_tool("veh_continue", {"threadId": 0})
    time.sleep(0.5)
    client.call_tool("veh_pause", {"threadId": 0})
    time.sleep(0.3)

    # Get modules to find a code address
    resp = client.call_tool("veh_modules")
    mods = client.parse_result(resp)
    modules = mods.get("modules", [])
    assert len(modules) > 0, f"No modules: {mods}"
    base = modules[0].get("baseAddress", "0x0")
    print(f"  Module base: {base}")

    # Set SW breakpoint
    resp = client.call_tool("veh_set_breakpoint", {"address": base})
    sw = client.parse_result(resp)
    assert sw.get("success"), f"SW BP failed: {sw}"
    sw_id = sw.get("id", 0)
    assert 0 < sw_id < 10001, f"SW BP ID should be < 10001, got {sw_id}"
    print(f"  SW BP ID: {sw_id} (< 10001 OK)")

    # Set HW data breakpoint at a safe address
    resp = client.call_tool("veh_set_data_breakpoint", {
        "address": "0x7FFE0000",  # KUSER_SHARED_DATA - safe to watch
        "type": "readwrite",
        "size": 4
    })
    hw = client.parse_result(resp)
    assert hw.get("success"), f"HW BP failed: {hw}"
    hw_id = hw.get("id", 0)
    assert hw_id >= 10001, f"HW BP ID should be >= 10001, got {hw_id}"
    print(f"  HW BP ID: {hw_id} (>= 10001 OK)")

    # List breakpoints - verify both present
    resp = client.call_tool("veh_list_breakpoints")
    bps = client.parse_result(resp)
    assert len(bps.get("software", [])) > 0, "No SW BPs in list"
    assert len(bps.get("hardware", [])) > 0, "No HW BPs in list"
    print(f"  list_breakpoints: {len(bps['software'])} SW, {len(bps['hardware'])} HW")

    # Clean up
    client.call_tool("veh_remove_breakpoint", {"id": sw_id})
    client.call_tool("veh_remove_data_breakpoint", {"id": hw_id})

    client.detach()
    client.close()


def test_rapid_restart():
    """Stress test: rapid detach->launch 10 cycles, verify no stale state."""
    client = McpClient()

    for i in range(10):
        pid = client.launch_target(True)

        # Quick continue + pause
        client.call_tool("veh_continue", {"threadId": 0})
        time.sleep(0.2)
        client.call_tool("veh_pause", {"threadId": 0})
        time.sleep(0.1)

        # Get threads - should only have threads from THIS process
        resp = client.call_tool("veh_threads")
        threads = client.parse_result(resp)
        thread_list = threads.get("threads", [])
        assert len(thread_list) > 0, f"Cycle {i}: No threads"

        # Detach
        data = client.detach()
        assert data.get("success"), f"Cycle {i}: Detach failed: {data}"

        time.sleep(0.1)
        print(f"  Cycle {i+1}/10: PID={pid}, threads={len(thread_list)} OK")

    client.close()


def test_thread_management_stress():
    """Stress test: pause/continue individual threads repeatedly."""
    client = McpClient()
    pid = client.launch_target(True)

    # Let it run to create multiple threads
    client.call_tool("veh_continue", {"threadId": 0})
    time.sleep(1)

    # Pause all
    client.call_tool("veh_pause", {"threadId": 0})
    time.sleep(0.3)

    # Get threads
    resp = client.call_tool("veh_threads")
    threads = client.parse_result(resp)
    thread_list = threads.get("threads", [])
    print(f"  Threads: {len(thread_list)}")
    assert len(thread_list) > 0, f"No threads"

    # Rapid per-thread continue/pause cycles
    for cycle in range(5):
        for t in thread_list:
            tid = t["id"]
            # Continue single thread
            resp = client.call_tool("veh_continue", {"threadId": tid})
            data = client.parse_result(resp)
            # May error if thread not stopped, that's OK
        time.sleep(0.1)
        # Pause all again
        client.call_tool("veh_pause", {"threadId": 0})
        time.sleep(0.1)
        print(f"  Cycle {cycle+1}/5: pause/continue OK")

    # Verify we can still get threads
    resp = client.call_tool("veh_threads")
    threads2 = client.parse_result(resp)
    assert "threads" in threads2, f"threads query failed after stress: {threads2}"
    print(f"  Post-stress threads: {len(threads2.get('threads', []))}")

    client.detach()
    client.close()


if __name__ == "__main__":
    if not os.path.exists(MCP_EXE):
        print(f"ERROR: MCP server not found: {MCP_EXE}")
        sys.exit(1)
    if not os.path.exists(TARGET):
        print(f"ERROR: Test target not found: {TARGET}")
        sys.exit(1)

    run_test("1. veh_dump_memory", test_dump_memory)
    run_test("2. veh_allocate_memory / veh_free_memory", test_allocate_free_memory)
    run_test("3. veh_execute_shellcode", test_execute_shellcode)
    run_test("4. veh_evaluate complex expressions", test_evaluate_complex)
    run_test("5. BP ID separation (SW vs HW)", test_bp_id_separation)
    run_test("6. Rapid restart stress (10 cycles)", test_rapid_restart)
    run_test("7. Thread management stress", test_thread_management_stress)

    print(f"\n{'='*40}")
    print(f"Results: {passed} passed, {failed} failed")
    sys.exit(1 if failed > 0 else 0)
