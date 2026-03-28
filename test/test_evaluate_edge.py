"""Edge case tests for evaluate extensions (gs:/fs:, [reg+offset]).

Tests:
1. gs:[0x60] - PEB access (x64 only, should work)
2. fs:[0x30] - should fail on x64 with clear error
3. [RSP] - single register dereference
4. [RSP+0x8] - reg + hex offset
5. [RSP-8] - reg - decimal offset
6. [RSP+RBP] - reg + reg
7. [] - empty brackets
8. [+] - operator only
9. [INVALID] - bad register name
10. [RSP+] - trailing operator
11. gs:[] - empty offset
12. gs:[abc] - non-numeric offset
13. *RSP - star with register (should resolve)
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
            [MCP_EXE], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.seq = 0
        self.send("initialize", {"protocolVersion": "2024-11-05",
                                  "capabilities": {},
                                  "clientInfo": {"name": "edge-test", "version": "1.0"}})
        resp = self.recv()
        assert resp and "result" in resp

    def send(self, method, params=None):
        self.seq += 1
        msg = {"jsonrpc": "2.0", "id": self.seq, "method": method}
        if params: msg["params"] = params
        self.proc.stdin.write((json.dumps(msg) + "\n").encode())
        self.proc.stdin.flush()

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


def run_all():
    client = McpClient()

    # Launch and pause
    r = client.parse(client.call_tool("veh_launch", {"program": TARGET, "stopOnEntry": True}))
    assert r.get("success"), f"Launch failed: {r}"
    pid = r["pid"]

    client.call_tool("veh_continue", {"threadId": 0})
    time.sleep(0.5)
    client.call_tool("veh_pause", {"threadId": 0})
    time.sleep(0.3)

    # Get thread
    threads = client.parse(client.call_tool("veh_threads"))
    tid = threads["threads"][0]["id"]
    print(f"  Thread: {tid}, PID: {pid}\n")

    def ev(expr):
        return client.parse(client.call_tool("veh_evaluate", {"expression": expr, "threadId": tid}))

    # === Positive cases ===
    test("gs:[0x60] PEB access", lambda: (
        (r := ev("gs:[0x60]")),
        assert_no_error(r, "gs:[0x60]"),
        assert_key(r, "tebAddress"),
    ))

    test("[RSP] single register deref", lambda: (
        (r := ev("[RSP]")),
        assert_no_error(r, "[RSP]"),
        assert_key(r, "value"),
    ))

    test("[RSP+0x8] reg+hex offset", lambda: (
        (r := ev("[RSP+0x8]")),
        assert_no_error(r, "[RSP+0x8]"),
        assert_key(r, "address"),
    ))

    test("[RSP-8] reg-decimal offset", lambda: (
        (r := ev("[RSP-8]")),
        assert_no_error(r, "[RSP-8]"),
    ))

    test("[RSP+RBP] reg+reg", lambda: (
        (r := ev("[RSP+RBP]")),
        assert_no_error(r, "[RSP+RBP]"),
    ))

    test("*RSP star with register", lambda: (
        (r := ev("*RSP")),
        # Should resolve RSP value then deref
        assert_no_error(r, "*RSP"),
    ))

    test("gs:[0x30] TEB self-reference", lambda: (
        (r := ev("gs:[0x30]")),
        assert_no_error(r, "gs:[0x30]"),
    ))

    # === Negative cases (should return error, not crash) ===
    test("fs:[0x30] rejected on x64", lambda: (
        (r := ev("fs:[0x30]")),
        assert_has_error(r, "fs:[0x30]"),
    ))

    test("[] empty brackets - no crash", lambda: (
        (r := ev("[]")),
        assert_has_error(r, "[]"),
    ))

    test("[+] operator only - no crash", lambda: (
        (r := ev("[+]")),
        assert_has_error(r, "[+]"),
    ))

    test("[INVALID] bad register - no crash", lambda: (
        (r := ev("[INVALID]")),
        assert_has_error(r, "[INVALID]"),
    ))

    test("[RSP+] trailing op - no crash", lambda: (
        (r := ev("[RSP+]")),
        assert_has_error(r, "[RSP+]"),
    ))

    test("gs:[] empty offset - no crash", lambda: (
        (r := ev("gs:[]")),
        assert_has_error(r, "gs:[]"),
    ))

    test("gs:[abc] non-numeric - no crash", lambda: (
        (r := ev("gs:[abc]")),
        assert_has_error(r, "gs:[abc]"),
    ))

    # Cleanup
    client.call_tool("veh_detach")
    client.close()


def assert_no_error(r, label):
    if "error" in r:
        raise AssertionError(f"{label} returned error: {r['error']}")

def assert_has_error(r, label):
    if "error" not in r:
        raise AssertionError(f"{label} should have returned error but got: {r}")

def assert_key(r, key):
    if key not in r:
        raise AssertionError(f"Missing key '{key}' in: {r}")


if __name__ == "__main__":
    if not os.path.exists(MCP_EXE):
        print(f"ERROR: {MCP_EXE} not found"); sys.exit(1)
    if not os.path.exists(TARGET):
        print(f"ERROR: {TARGET} not found"); sys.exit(1)

    print("=== Evaluate Edge Case Tests ===\n")
    run_all()
    print(f"\n{'='*40}")
    print(f"Results: {passed} passed, {failed} failed")
    sys.exit(1 if failed > 0 else 0)
