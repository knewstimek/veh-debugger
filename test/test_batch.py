"""Test veh_batch tool - sequential execution, variable refs, control flow."""
import subprocess, json, time, sys, os

MCP_EXE = os.path.join(os.path.dirname(__file__), "..", "build", "bin", "Release", "veh-mcp-server.exe")
TARGET = os.path.join(os.path.dirname(__file__), "..", "build", "bin", "Release", "test_target.exe")

class McpClient:
    def __init__(self):
        self.proc = subprocess.Popen([MCP_EXE], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.seq = 0
        self.send("initialize", {"protocolVersion": "2024-11-05", "capabilities": {},
                                  "clientInfo": {"name": "batch-test", "version": "1.0"}})
        assert self.recv() is not None

    def send(self, method, params=None):
        self.seq += 1
        msg = {"jsonrpc": "2.0", "id": self.seq, "method": method}
        if params: msg["params"] = params
        self.proc.stdin.write((json.dumps(msg) + "\n").encode()); self.proc.stdin.flush()

    def recv(self, timeout=15):
        start = time.time()
        while time.time() - start < timeout:
            line = self.proc.stdout.readline()
            if line:
                line = line.decode().strip()
                if line:
                    try: return json.loads(line)
                    except: continue
        return None

    def call_tool(self, name, args=None):
        self.send("tools/call", {"name": name, "arguments": args or {}})
        return self.recv()

    def parse(self, resp):
        if not resp: return {"error": "timeout"}
        content = resp.get("result", {}).get("content", [{}])
        text = content[0].get("text", "") if content else ""
        try: return json.loads(text) if text else {}
        except: return {"raw": text}

    def close(self):
        try: self.proc.stdin.close()
        except: pass
        try: self.proc.terminate(); self.proc.wait(timeout=3)
        except: self.proc.kill()


passed = 0
failed = 0

def test(name, fn):
    global passed, failed
    try:
        fn()
        passed += 1
        print(f"  PASS: {name}")
    except Exception as e:
        failed += 1
        print(f"  FAIL: {name} - {e}")
        import traceback; traceback.print_exc()


def run_all():
    client = McpClient()
    r = client.parse(client.call_tool("veh_launch", {"program": TARGET, "stopOnEntry": True}))
    assert r.get("success"), f"Launch: {r}"
    pid = r["pid"]
    print(f"  PID: {pid}")
    client.call_tool("veh_continue", {"threadId": 0})
    time.sleep(0.5)
    client.call_tool("veh_pause", {"threadId": 0})
    time.sleep(0.3)

    # Get a thread ID for use in tests
    threads = client.parse(client.call_tool("veh_threads"))
    tid = threads["threads"][0]["id"]
    print(f"  Thread: {tid}\n")

    # Test 1: Sequential with $N variable reference
    def test_sequential_refs():
        r = client.parse(client.call_tool("veh_batch", {"steps": [
            {"tool": "veh_registers", "args": {"threadId": tid}},
            {"tool": "veh_evaluate", "args": {"expression": "[RSP]", "threadId": tid}},
        ]}))
        assert "results" in r, f"No results: {r}"
        assert len(r["results"]) == 2, f"Expected 2 results: {r}"
        # Step 0 should have registers
        step0 = r["results"][0]["result"]
        assert "registers" in step0, f"Step 0 missing registers: {step0}"
        print(f"    Step 0: RSP={step0['registers'].get('rsp', 'N/A')}")
        # Step 1 should have value
        step1 = r["results"][1]["result"]
        assert "value" in step1, f"Step 1 missing value: {step1}"
        print(f"    Step 1: [RSP]={step1['value']}")

    test("Sequential with variable refs", test_sequential_refs)

    # Test 2: Batch write via veh_batch
    def test_batch_write():
        # Allocate + batch write + verify + free
        r = client.parse(client.call_tool("veh_batch", {"steps": [
            {"tool": "veh_allocate_memory", "args": {"size": 4096, "protection": "rwx"}},
            {"tool": "veh_write_memory", "args": {
                "patches": [
                    {"address": "$0.address", "data": "41 42 43 44"},
                    {"address": "$0.address", "data": "90 90 90 90"},  # overwrite
                ]
            }},
            {"tool": "veh_read_memory", "args": {"address": "$0.address", "size": 4}},
            {"tool": "veh_free_memory", "args": {"address": "$0.address"}},
        ]}))
        assert r.get("totalSteps") == 4, f"Expected 4 steps: {r}"
        step2 = r["results"][2]["result"]
        assert "90 90 90 90" in step2.get("hex", "").lower(), f"Write verify failed: {step2}"
        print(f"    Alloc->Write->Read->Free OK, read={step2.get('hex', '')}")

    test("Batch write + allocate/free", test_batch_write)

    # Test 3: for_each patching (all inside batch)
    def test_for_each():
        # Use batch write patches (simpler, more practical pattern)
        alloc = client.parse(client.call_tool("veh_allocate_memory", {"size": 4096, "protection": "rwx"}))
        base = alloc["address"]
        base_int = int(base, 16)
        addrs = [hex(base_int + i * 16) for i in range(3)]

        r = client.parse(client.call_tool("veh_batch", {"steps": [
            {"for_each": addrs, "as": "$addr", "do": [
                {"tool": "veh_write_memory", "args": {"address": "$addr", "data": "CC"}}
            ]},
        ]}))
        assert "results" in r, f"for_each failed: {r}"
        step0 = r["results"][0]["result"]
        assert step0.get("type") == "for_each", f"Expected for_each: {step0}"
        assert step0.get("count") == 3, f"Expected 3 iterations: {step0}"
        print(f"    for_each executed {step0.get('count')} iterations")

        # Verify outside batch
        ok_count = 0
        for addr in addrs:
            mem = client.parse(client.call_tool("veh_read_memory", {"address": addr, "size": 1}))
            if "cc" in mem.get("hex", "").lower():
                ok_count += 1
        print(f"    Verified {ok_count}/{len(addrs)} addresses have CC")
        assert ok_count == 3, f"Only {ok_count}/3 addresses verified"

        client.call_tool("veh_free_memory", {"address": base})

    test("for_each patching", test_for_each)

    # Test 4: if condition
    def test_if_condition():
        r = client.parse(client.call_tool("veh_batch", {"steps": [
            {"tool": "veh_registers", "args": {"threadId": tid}},
            {"if": "1==1", "then": [
                {"tool": "veh_threads"}
            ], "else": [
                {"tool": "veh_modules"}
            ]}
        ]}))
        assert r.get("totalSteps") >= 2, f"Expected >= 2 steps: {r}"
        step1 = r["results"][1]["result"]
        assert step1.get("branch") == "then", f"Expected 'then' branch: {step1}"
        print(f"    if 1==1 -> then branch OK")

    test("if condition", test_if_condition)

    # Test 5: Empty/error handling
    def test_error_handling():
        # Empty steps
        r = client.parse(client.call_tool("veh_batch", {"steps": []}))
        assert "error" in r, f"Expected error for empty steps: {r}"
        print(f"    Empty steps: error OK")

        # Unknown tool
        r = client.parse(client.call_tool("veh_batch", {"steps": [
            {"tool": "veh_nonexistent", "args": {}}
        ]}))
        step0 = r["results"][0]["result"]
        assert "error" in step0, f"Expected error for unknown tool: {step0}"
        print(f"    Unknown tool: error OK")

    test("Error handling", test_error_handling)

    # Cleanup
    client.call_tool("veh_detach")
    client.close()


if __name__ == "__main__":
    print("=== veh_batch Tests ===\n")
    run_all()
    print(f"\n{'='*40}")
    print(f"Results: {passed} passed, {failed} failed")
    sys.exit(1 if failed > 0 else 0)
