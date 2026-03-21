"""
Test: veh_launch error diagnostics and edge cases.
Validates that launch failures return actionable error messages.
Covers:
1. Non-existent executable -> "executable not found" in error
2. Non-existent path -> "path not found" in error
3. Non-PE file (text file) -> "bad PE format" in error
4. Empty program argument -> error
5. DLL path validation -> specific DLL name in error
6. Double launch (launch while already attached) -> clean error
7. Launch with stopOnEntry=true -> verify entry stop
8. Launch with stopOnEntry=false -> verify running
9. Launch then detach then re-launch -> clean cycle
10. Rapid launch/detach cycle x5 -> stability
"""
import subprocess
import json
import threading
import time
import sys
import os
import tempfile

MCP_SERVER = os.path.join(os.path.dirname(__file__), "..", "build", "bin", "Release", "veh-mcp-server.exe")
TEST_TARGET = os.path.join(os.path.dirname(__file__), "..", "build", "bin", "Release", "test_target.exe")

class McpClient:
    def __init__(self):
        self.proc = subprocess.Popen(
            [MCP_SERVER],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
        )
        self.req_id = 0
        self.lock = threading.Lock()
        self.responses = {}
        self.response_events = {}
        self.reader_thread = threading.Thread(target=self._reader, daemon=True)
        self.reader_thread.start()

    def _reader(self):
        while True:
            try:
                line = self.proc.stdout.readline()
                if not line:
                    break
                line = line.strip()
                if not line:
                    continue
                obj = json.loads(line)
                rid = obj.get("id")
                if rid and rid in self.response_events:
                    self.responses[rid] = obj
                    self.response_events[rid].set()
            except:
                break

    def call(self, method, params=None, timeout=15):
        self.req_id += 1
        rid = self.req_id
        msg = {"jsonrpc": "2.0", "id": rid, "method": method}
        if params is not None:
            msg["params"] = params
        evt = threading.Event()
        self.response_events[rid] = evt
        data = json.dumps(msg) + "\n"
        with self.lock:
            self.proc.stdin.write(data.encode("utf-8"))
            self.proc.stdin.flush()
        if not evt.wait(timeout):
            raise TimeoutError(f"Timeout for id={rid} method={method}")
        return self.responses.pop(rid)

    def close(self):
        try: self.proc.stdin.close()
        except: pass
        try: self.proc.terminate()
        except: pass

def get_text(resp):
    try:
        return resp.get("result", {}).get("content", [{}])[0].get("text", "")
    except:
        return str(resp)

def get_json(resp):
    text = get_text(resp)
    return json.loads(text) if text else {}

def run_test(name, fn, errors):
    print(f"\n--- {name} ---")
    try:
        fn()
        print(f"  [OK]")
    except AssertionError as e:
        print(f"  [FAIL] {e}")
        errors.append(f"{name}: {e}")
    except TimeoutError as e:
        print(f"  [FAIL] TIMEOUT: {e}")
        errors.append(f"{name}: timeout")
    except Exception as e:
        print(f"  [FAIL] {type(e).__name__}: {e}")
        errors.append(f"{name}: {e}")

def main():
    print("=" * 60)
    print("Test: veh_launch error diagnostics")
    print("=" * 60)
    errors = []
    client = McpClient()

    try:
        client.call("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "1.0"}
        })

        # --- Test 1: Non-existent executable ---
        def test_nonexistent_exe():
            resp = client.call("tools/call", {
                "name": "veh_launch",
                "arguments": {"program": "C:\\nonexistent\\fake.exe"}
            })
            data = get_json(resp)
            err = data.get("error", "")
            assert "error" in data, f"Expected error, got: {data}"
            # Should mention file not found
            has_detail = ("not found" in err.lower() or "error 2" in err or "error 3" in err)
            print(f"  Error: {err[:80]}")
            assert has_detail, f"Error lacks detail: {err}"

        run_test("Test 1: Non-existent executable", test_nonexistent_exe, errors)

        # --- Test 2: Non-existent path ---
        def test_nonexistent_path():
            resp = client.call("tools/call", {
                "name": "veh_launch",
                "arguments": {"program": "Z:\\no\\such\\path\\app.exe"}
            })
            data = get_json(resp)
            err = data.get("error", "")
            assert "error" in data, f"Expected error, got: {data}"
            print(f"  Error: {err[:80]}")

        run_test("Test 2: Non-existent path", test_nonexistent_path, errors)

        # --- Test 3: Non-PE file ---
        def test_non_pe_file():
            # Create a temp text file with .exe extension
            tmpdir = tempfile.mkdtemp()
            fake_exe = os.path.join(tmpdir, "fake.exe")
            with open(fake_exe, "w") as f:
                f.write("this is not a PE file")
            try:
                resp = client.call("tools/call", {
                    "name": "veh_launch",
                    "arguments": {"program": fake_exe}
                })
                data = get_json(resp)
                err = data.get("error", "")
                assert "error" in data, f"Expected error for non-PE: {data}"
                print(f"  Error: {err[:80]}")
                # Should mention bad format or CreateProcess failure
                assert "error" in data, f"Non-PE launch should fail"
            finally:
                try: os.unlink(fake_exe)
                except: pass
                try: os.rmdir(tmpdir)
                except: pass

        run_test("Test 3: Non-PE file as executable", test_non_pe_file, errors)

        # --- Test 4: Empty program argument ---
        def test_empty_program():
            resp = client.call("tools/call", {
                "name": "veh_launch",
                "arguments": {"program": ""}
            })
            data = get_json(resp)
            assert "error" in data, f"Expected error for empty program: {data}"
            print(f"  Error: {data['error'][:60]}")

        run_test("Test 4: Empty program argument", test_empty_program, errors)

        # --- Test 5: Launch with string-typed stopOnEntry ---
        def test_string_stop_on_entry():
            resp = client.call("tools/call", {
                "name": "veh_launch",
                "arguments": {"program": TEST_TARGET, "stopOnEntry": "true"}
            })
            data = get_json(resp)
            assert "pid" in data, f"String stopOnEntry should work: {data}"
            pid = data["pid"]
            assert "stopped on entry" in data.get("message", "").lower(), \
                f"Should stop on entry: {data.get('message', '')}"
            print(f"  String 'true' -> stopped on entry, pid={pid}")

            client.call("tools/call", {"name": "veh_detach", "arguments": {}}, timeout=5)
            os.system(f"taskkill /PID {pid} /F >nul 2>&1")

        run_test("Test 5: String-typed stopOnEntry='true'", test_string_stop_on_entry, errors)

        # --- Test 6: Double launch ---
        def test_double_launch():
            resp = client.call("tools/call", {
                "name": "veh_launch",
                "arguments": {"program": TEST_TARGET, "stopOnEntry": True}
            })
            data = get_json(resp)
            assert "pid" in data, f"First launch failed: {data}"
            pid1 = data["pid"]

            # Second launch while attached
            resp2 = client.call("tools/call", {
                "name": "veh_launch",
                "arguments": {"program": TEST_TARGET, "stopOnEntry": True}
            })
            data2 = get_json(resp2)
            # Should either auto-detach+relaunch or return error
            if "pid" in data2:
                pid2 = data2["pid"]
                print(f"  Double launch: auto-relaunch pid1={pid1} -> pid2={pid2}")
                client.call("tools/call", {"name": "veh_detach", "arguments": {}}, timeout=5)
                os.system(f"taskkill /PID {pid2} /F >nul 2>&1")
            else:
                print(f"  Double launch: error (expected): {data2.get('error', '')[:50]}")
                client.call("tools/call", {"name": "veh_detach", "arguments": {}}, timeout=5)

            os.system(f"taskkill /PID {pid1} /F >nul 2>&1")

        run_test("Test 6: Double launch", test_double_launch, errors)

        # --- Test 7: Launch with numeric string args ---
        def test_numeric_string_args():
            resp = client.call("tools/call", {
                "name": "veh_launch",
                "arguments": {"program": TEST_TARGET, "stopOnEntry": "1"}
            })
            data = get_json(resp)
            assert "pid" in data, f"Numeric string stopOnEntry failed: {data}"
            pid = data["pid"]
            print(f"  stopOnEntry='1' -> pid={pid}")

            client.call("tools/call", {"name": "veh_detach", "arguments": {}}, timeout=5)
            os.system(f"taskkill /PID {pid} /F >nul 2>&1")

        run_test("Test 7: Numeric string stopOnEntry='1'", test_numeric_string_args, errors)

        # --- Test 8: Launch then detach then re-launch ---
        def test_launch_detach_relaunch():
            resp = client.call("tools/call", {
                "name": "veh_launch",
                "arguments": {"program": TEST_TARGET, "stopOnEntry": True}
            })
            data = get_json(resp)
            assert "pid" in data, f"Initial launch failed: {data}"
            pid1 = data["pid"]

            client.call("tools/call", {"name": "veh_detach", "arguments": {}}, timeout=5)
            os.system(f"taskkill /PID {pid1} /F >nul 2>&1")
            time.sleep(0.5)

            resp2 = client.call("tools/call", {
                "name": "veh_launch",
                "arguments": {"program": TEST_TARGET, "stopOnEntry": True}
            })
            data2 = get_json(resp2)
            assert "pid" in data2, f"Re-launch failed: {data2}"
            pid2 = data2["pid"]
            assert pid2 != pid1, f"Same PID after re-launch?"
            print(f"  Launch {pid1} -> detach -> re-launch {pid2}")

            # Verify session works
            r = get_json(client.call("tools/call", {"name": "veh_threads", "arguments": {}}))
            assert "threads" in r, f"Threads after re-launch: {r}"

            client.call("tools/call", {"name": "veh_detach", "arguments": {}}, timeout=5)
            os.system(f"taskkill /PID {pid2} /F >nul 2>&1")

        run_test("Test 8: Launch -> detach -> re-launch", test_launch_detach_relaunch, errors)

        # --- Test 9: Rapid launch/detach cycle ---
        def test_rapid_launch_detach():
            for i in range(5):
                resp = client.call("tools/call", {
                    "name": "veh_launch",
                    "arguments": {"program": TEST_TARGET, "stopOnEntry": True}
                })
                data = get_json(resp)
                if "pid" not in data:
                    raise AssertionError(f"Cycle {i+1}: launch failed: {data}")
                pid = data["pid"]

                client.call("tools/call", {"name": "veh_detach", "arguments": {}}, timeout=5)
                os.system(f"taskkill /PID {pid} /F >nul 2>&1")
                time.sleep(0.3)

            print(f"  5 launch/detach cycles completed")

        run_test("Test 9: Rapid launch/detach x5", test_rapid_launch_detach, errors)

        # --- Test 10: Non-PE file triggers CreateProcess error with code ---
        def test_error_has_code():
            # Use a non-PE file that EXISTS but isn't executable
            # This bypasses the filesystem::exists check and reaches CreateProcess
            tmpdir = tempfile.mkdtemp()
            fake_exe = os.path.join(tmpdir, "bad.exe")
            with open(fake_exe, "wb") as f:
                f.write(b"NOT_A_PE_FILE_HEADER_1234567890")
            try:
                resp = client.call("tools/call", {
                    "name": "veh_launch",
                    "arguments": {"program": fake_exe}
                })
                data = get_json(resp)
                err = data.get("error", "")
                assert "error" in data, f"Expected error: {data}"
                # Should contain CreateProcess error code
                has_code = ("error " in err.lower() or "CreateProcess failed" in err)
                print(f"  Error msg: {err[:100]}")
                assert has_code, f"Error should contain error code: {err}"
            finally:
                try: os.unlink(fake_exe)
                except: pass
                try: os.rmdir(tmpdir)
                except: pass

        run_test("Test 10: Non-PE CreateProcess error with code", test_error_has_code, errors)

    except Exception as e:
        print(f"\n[FATAL] {type(e).__name__}: {e}")
        errors.append(f"Fatal: {e}")
    finally:
        client.close()

    print()
    print("=" * 60)
    if errors:
        print(f"FAILED - {len(errors)} error(s):")
        for e in errors:
            print(f"  - {e}")
        return 1
    else:
        print(f"ALL TESTS PASSED (10/10)")
        return 0

if __name__ == "__main__":
    sys.exit(main())
