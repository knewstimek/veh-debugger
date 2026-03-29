"""Test batch write and pass_exception features.

1. batch write - multiple patches in one call
2. pass_exception - forward exception to SEH (verify no crash)
3. shellcode crash reporting
4. dump_memory SHA256 checksum
"""
import subprocess
import json
import time
import sys
import os
import tempfile
import hashlib

MCP_EXE = os.path.join(os.path.dirname(__file__), "..", "build", "bin", "Release", "veh-mcp-server.exe")
TARGET = os.path.join(os.path.dirname(__file__), "..", "build", "bin", "Release", "test_target.exe")

class McpClient:
    def __init__(self):
        self.proc = subprocess.Popen(
            [MCP_EXE], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.seq = 0
        self.send("initialize", {"protocolVersion": "2024-11-05",
                                  "capabilities": {},
                                  "clientInfo": {"name": "batch-test", "version": "1.0"}})
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

    def call_tool(self, name, args=None, timeout=15):
        self.send("tools/call", {"name": name, "arguments": args or {}})
        return self.recv(timeout=timeout)

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
        import traceback
        traceback.print_exc()


def run_all():
    client = McpClient()
    pid = client.parse(client.call_tool("veh_launch", {"program": TARGET, "stopOnEntry": True}))
    assert pid.get("success"), f"Launch failed: {pid}"
    print(f"  PID: {pid['pid']}")

    client.call_tool("veh_continue", {"threadId": 0})
    time.sleep(0.5)
    client.call_tool("veh_pause", {"threadId": 0})
    time.sleep(0.3)

    # --- Test 1: Batch Write ---
    def test_batch_write():
        # Allocate RWX page for safe writing
        r = client.parse(client.call_tool("veh_allocate_memory", {"size": 4096, "protection": "rwx"}))
        assert r.get("success"), f"alloc failed: {r}"
        base = r["address"]
        base_int = int(base, 16)

        # Batch write 5 patches
        patches = []
        for i in range(5):
            addr = hex(base_int + i * 16)
            patches.append({"address": addr, "data": f"{'%02X' % (0x41 + i)} 90 90 C3"})

        r = client.parse(client.call_tool("veh_write_memory", {"patches": patches}))
        assert r.get("success"), f"batch write failed: {r}"
        assert r.get("succeeded") == 5, f"Expected 5 succeeded, got {r.get('succeeded')}"
        assert r.get("failed") == 0, f"Expected 0 failed, got {r.get('failed')}"
        print(f"    Batch: 5/5 patches OK")

        # Verify first patch
        r = client.parse(client.call_tool("veh_read_memory", {"address": base, "size": 4}))
        assert "41 90 90 c3" in r.get("hex", "").lower(), f"Verify failed: {r}"
        print(f"    Verified: {r.get('hex')}")

        # Batch with some invalid addresses
        bad_patches = [
            {"address": base, "data": "CC"},
            {"address": "invalid", "data": "90"},
            {"address": hex(base_int + 16), "data": "CC"},
        ]
        r = client.parse(client.call_tool("veh_write_memory", {"patches": bad_patches}))
        assert r.get("succeeded") == 2, f"Expected 2 succeeded: {r}"
        assert r.get("failed") == 1, f"Expected 1 failed: {r}"
        print(f"    Mixed batch: 2 ok, 1 fail OK")

        client.call_tool("veh_free_memory", {"address": base})

    test("Batch write (5 patches + mixed)", test_batch_write)

    # --- Test 2: pass_exception ---
    def test_pass_exception():
        # Set a BP, continue with wait to hit it... but test_target might not hit it.
        # Instead, test that pass_exception parameter is accepted and doesn't crash.
        # Continue with pass_exception=true, no wait (should succeed)
        r = client.parse(client.call_tool("veh_continue", {
            "threadId": 0, "pass_exception": True
        }))
        # Should succeed (process was paused, continuing with pass_exception)
        assert "error" not in r, f"pass_exception continue failed: {r}"
        print(f"    pass_exception=true accepted: {r.get('success', r.get('stopped', 'ok'))}")

        time.sleep(0.3)
        client.call_tool("veh_pause", {"threadId": 0})
        time.sleep(0.2)

        # Continue with pass_exception=false (normal, should also work)
        r = client.parse(client.call_tool("veh_continue", {
            "threadId": 0, "pass_exception": False
        }))
        assert "error" not in r, f"normal continue failed: {r}"
        print(f"    pass_exception=false OK")

        time.sleep(0.3)
        client.call_tool("veh_pause", {"threadId": 0})
        time.sleep(0.2)

    test("pass_exception parameter", test_pass_exception)

    # --- Test 3: Shellcode crash reporting ---
    def test_shellcode_crash():
        # Shellcode that crashes: mov rax, 0; mov [rax], rax (ACCESS_VIOLATION)
        # x64: 48 31 C0 48 89 00
        r = client.parse(client.call_tool("veh_execute_shellcode", {
            "shellcode": "4831C0488900",
            "timeout_ms": 5000
        }))
        # Should report crash
        assert r.get("crashed") == True, f"Expected crashed=true: {r}"
        assert r.get("exceptionCode") is not None, f"Missing exceptionCode: {r}"
        print(f"    Crash reported: code={r.get('exceptionCode')}, addr={r.get('exceptionAddress')}")

        # Normal shellcode should still work after crash
        r = client.parse(client.call_tool("veh_execute_shellcode", {
            "shellcode": "33C0C3",
            "timeout_ms": 5000
        }))
        assert r.get("success"), f"Post-crash shellcode failed: {r}"
        assert r.get("exitCode") == 0, f"Expected exitCode=0: {r}"
        print(f"    Post-crash shellcode OK, exitCode={r['exitCode']}")

    test("Shellcode crash reporting", test_shellcode_crash)

    # --- Test 4: dump_memory SHA256 ---
    def test_dump_sha256():
        # Get modules for stable address
        mods = client.parse(client.call_tool("veh_modules"))
        base = mods["modules"][0]["baseAddress"]

        dump_path = os.path.join(tempfile.gettempdir(), "veh_sha256_test.bin")
        r = client.parse(client.call_tool("veh_dump_memory", {
            "address": base, "size": 512, "output_path": dump_path
        }))
        assert r.get("success"), f"dump failed: {r}"
        assert "sha256" in r, f"Missing sha256: {r}"
        assert r.get("verified") == True, f"Not verified: {r}"

        # Verify SHA256 locally
        with open(dump_path, "rb") as f:
            local_hash = hashlib.sha256(f.read()).hexdigest()
        assert local_hash == r["sha256"], \
            f"SHA256 mismatch: local={local_hash} vs server={r['sha256']}"
        print(f"    SHA256 match: {local_hash[:16]}...")

        os.unlink(dump_path)

    test("dump_memory SHA256 checksum", test_dump_sha256)

    # Cleanup
    client.call_tool("veh_detach")
    client.close()


if __name__ == "__main__":
    if not os.path.exists(MCP_EXE):
        print(f"ERROR: {MCP_EXE}"); sys.exit(1)
    if not os.path.exists(TARGET):
        print(f"ERROR: {TARGET}"); sys.exit(1)

    print("=== Batch Write + Pass Exception + Crash Report + SHA256 Tests ===\n")
    run_all()
    print(f"\n{'='*40}")
    print(f"Results: {passed} passed, {failed} failed")
    sys.exit(1 if failed > 0 else 0)
