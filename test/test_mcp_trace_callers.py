"""MCP veh_trace_callers test.

Sets a breakpoint on WorkFunction, collects callers for 3 seconds,
verifies at least 1 unique caller with multiple hits.
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

    def recv(self, timeout=30):
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

    def call_tool(self, name, args=None, timeout=30):
        self.send("tools/call", {"name": name, "arguments": args or {}})
        return self.recv(timeout=timeout)

    def close(self):
        try: self.proc.stdin.close()
        except: pass
        try: self.proc.terminate()
        except: pass
        try: self.proc.wait(timeout=3)
        except: pass

def get_content(resp):
    """Extract JSON from MCP tool response."""
    try:
        text = resp["result"]["content"][0]["text"]
        return json.loads(text)
    except:
        return resp

def main():
    print("=== MCP TraceCallers Test ===\n")
    c = McpClient()

    try:
        # 1. Initialize
        c.send("initialize", {"protocolVersion": "2024-11-05",
                              "clientInfo": {"name": "test", "version": "1.0"},
                              "capabilities": {}})
        r = c.recv()
        print("1. Initialize OK")

        # 2. Launch
        r = c.call_tool("veh_launch", {"program": TARGET, "stopOnEntry": False})
        data = get_content(r)
        pid = data.get("pid")
        print(f"2. Launched PID={pid}")

        # 3. Find WorkFunction address via modules + disassembly
        r = c.call_tool("veh_modules")
        modules = get_content(r)
        base = None
        for m in modules.get("modules", []):
            if "test_target" in m.get("name", "").lower():
                base = int(m["baseAddress"], 16)
                break
        assert base is not None, "test_target module not found"
        print(f"3. test_target base=0x{base:X}")

        # Disassemble from .text to find WorkFunction (first function before main's loop)
        # WorkFunction starts right at base+0x1000 typically
        r = c.call_tool("veh_disassemble", {"address": f"0x{base + 0x1000:X}", "count": 50})
        disasm = get_content(r)

        # Find first RET - that's end of WorkFunction, WorkFunction entry = base+0x1000
        work_func = base + 0x1000
        print(f"4. WorkFunction estimated at 0x{work_func:X}")

        # 4. Give process time to start its loop
        time.sleep(1)

        # 5. Call trace_callers (3 second duration)
        print("5. Calling veh_trace_callers (3 sec)...")
        r = c.call_tool("veh_trace_callers", {
            "address": f"0x{work_func:X}",
            "duration_sec": 3
        }, timeout=20)
        data = get_content(r)
        print(f"   Result: {json.dumps(data, indent=2)}")

        # 6. Verify results
        if "error" in data:
            print(f"\n>>> FAIL: Got error: {data['error']}")
            sys.exit(1)

        total_hits = data.get("totalHits", 0)
        unique_callers = data.get("uniqueCallers", 0)
        callers = data.get("callers", [])

        print(f"\n6. Verification:")
        print(f"   totalHits={total_hits}")
        print(f"   uniqueCallers={unique_callers}")
        print(f"   callers={callers}")

        if total_hits < 1:
            print(">>> FAIL: Expected at least 1 hit")
            sys.exit(1)

        if unique_callers < 1:
            print(">>> FAIL: Expected at least 1 unique caller")
            sys.exit(1)

        if len(callers) != unique_callers:
            print(f">>> FAIL: callers array length ({len(callers)}) != uniqueCallers ({unique_callers})")
            sys.exit(1)

        # Verify each caller has address and hitCount
        for caller in callers:
            assert "address" in caller, "Missing address in caller entry"
            assert "hitCount" in caller, "Missing hitCount in caller entry"
            assert caller["hitCount"] > 0, "hitCount should be > 0"
            print(f"   Caller: {caller['address']} (hits: {caller['hitCount']})")

        print("\n>>> PASS: TraceCallers working correctly!")

    finally:
        # Cleanup
        try: c.call_tool("veh_detach")
        except: pass
        c.close()
        # Kill any remaining test_target
        os.system("taskkill /IM test_target.exe /F >nul 2>&1")

if __name__ == "__main__":
    main()
