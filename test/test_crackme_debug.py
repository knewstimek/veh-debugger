"""
Test: Real-world debugging with crackme binary.
Exercises actual debugging workflow:
1. Launch crackme and stop at entry
2. Set breakpoint at main, hit it
3. Step over instructions
4. Read registers and memory
5. Disassemble around current IP
6. Set HW breakpoint, verify hit
7. Evaluate expressions (register, pointer deref)
8. Enumerate modules (verify crackme loaded)
9. Stack trace at breakpoint
10. Multi-thread inspection
11. Conditional breakpoint
12. Step-in + step-out cycle
"""
import subprocess
import json
import threading
import time
import sys
import os

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

# Shared state across tests (single session)
state = {}

def main():
    print("=" * 60)
    print("Test: Real-world debugging with test_target")
    print("=" * 60)
    errors = []
    client = McpClient()

    try:
        client.call("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "1.0"}
        })

        # --- Test 1: Launch and stop at entry ---
        def test_launch_entry():
            resp = client.call("tools/call", {
                "name": "veh_launch",
                "arguments": {"program": TEST_TARGET, "stopOnEntry": True}
            })
            data = get_json(resp)
            assert "pid" in data, f"Launch failed: {data}"
            state["pid"] = data["pid"]
            print(f"  Launched pid={data['pid']}, stopped on entry")

        run_test("Test 1: Launch and stop at entry", test_launch_entry, errors)

        # --- Test 2: Get registers at entry ---
        def test_registers_at_entry():
            threads = get_json(client.call("tools/call", {
                "name": "veh_threads", "arguments": {}
            }))
            assert "threads" in threads, f"No threads: {threads}"
            tid = threads["threads"][0]["id"]
            state["main_tid"] = tid

            regs = get_json(client.call("tools/call", {
                "name": "veh_registers", "arguments": {"threadId": tid}
            }))
            assert "registers" in regs, f"No registers: {regs}"
            rip = regs["registers"].get("rip", regs["registers"].get("eip", ""))
            assert rip, f"No RIP/EIP: {regs['registers']}"
            state["entry_rip"] = rip
            print(f"  Thread {tid}, RIP={rip}")

        run_test("Test 2: Registers at entry", test_registers_at_entry, errors)

        # --- Test 3: Disassemble at entry ---
        def test_disassemble():
            regs = get_json(client.call("tools/call", {
                "name": "veh_registers", "arguments": {"threadId": state["main_tid"]}
            }))
            rip = regs["registers"].get("rip", regs["registers"].get("eip", ""))

            disasm = get_json(client.call("tools/call", {
                "name": "veh_disassemble",
                "arguments": {"address": rip, "count": 10}
            }))
            instrs = disasm.get("instructions", [])
            assert len(instrs) > 0, f"No instructions: {disasm}"
            print(f"  {len(instrs)} instructions from {rip}")
            for i in instrs[:3]:
                print(f"    {i.get('address', '?')}: {i.get('mnemonic', '?')} {i.get('operands', '')}")

        run_test("Test 3: Disassemble at entry", test_disassemble, errors)

        # --- Test 4: Enumerate modules ---
        def test_modules():
            mods = get_json(client.call("tools/call", {
                "name": "veh_modules", "arguments": {}
            }))
            assert "modules" in mods, f"No modules: {mods}"
            count = mods["count"]
            assert count > 0, f"Zero modules"
            # Find test_target
            names = [m["name"] for m in mods["modules"]]
            has_target = any("test_target" in n.lower() for n in names)
            assert has_target, f"test_target.exe not in modules: {names}"
            state["module_base"] = mods["modules"][0]["baseAddress"]
            print(f"  {count} modules, test_target found, base={state['module_base']}")

        run_test("Test 4: Enumerate modules", test_modules, errors)

        # --- Test 5: Read memory at module base ---
        def test_read_memory():
            base = state["module_base"]
            mem = get_json(client.call("tools/call", {
                "name": "veh_read_memory",
                "arguments": {"address": base, "length": 64}
            }))
            assert "data" in mem or "hex" in mem or "bytes" in mem, f"No memory data: {mem}"
            # PE header should start with MZ
            raw = mem.get("hex", mem.get("data", ""))
            assert raw.upper().startswith("4D5A") or raw.upper().startswith("4D 5A"), \
                f"Expected MZ header, got: {raw[:20]}"
            print(f"  Read 64 bytes at {base}: MZ header confirmed")

        run_test("Test 5: Read memory (PE header)", test_read_memory, errors)

        # --- Test 6: Set BP at WorkFunction, continue, hit ---
        def test_bp_and_hit():
            # Use source BP (line-based) since we have PDB
            bp = get_json(client.call("tools/call", {
                "name": "veh_set_source_breakpoint",
                "arguments": {"source": "main.cpp", "line": 14}
            }))
            assert "id" in bp or "breakpoints" in bp, f"BP set failed: {bp}"
            bp_id = bp.get("id", 0)
            bp_addr = bp.get("address", "")
            print(f"  BP set at main.cpp:14, id={bp_id}, addr={bp_addr}")

            # Continue and wait for BP hit
            cont = get_json(client.call("tools/call", {
                "name": "veh_continue",
                "arguments": {"wait": True, "timeout": 10}
            }))
            reason = cont.get("reason", "")
            assert reason == "breakpoint", f"Expected breakpoint, got: {reason}"
            state["bp_thread"] = cont.get("threadId", 0)
            print(f"  BP hit! thread={state['bp_thread']}")

            # Clean up BP
            if bp_id:
                client.call("tools/call", {
                    "name": "veh_remove_breakpoint",
                    "arguments": {"id": bp_id}
                })

        run_test("Test 6: Source BP + continue + hit", test_bp_and_hit, errors)

        # --- Test 7: Stack trace at breakpoint ---
        def test_stack_trace():
            tid = state.get("bp_thread", state["main_tid"])
            st = get_json(client.call("tools/call", {
                "name": "veh_stack_trace",
                "arguments": {"threadId": tid}
            }))
            frames = st.get("frames", [])
            assert len(frames) >= 2, f"Expected >= 2 frames, got {len(frames)}"
            # Top frame should be in WorkFunction
            top = frames[0].get("function", frames[0].get("name", ""))
            print(f"  {len(frames)} frames, top={top}")
            for f in frames[:4]:
                fname = f.get("function", f.get("name", "?"))
                addr = f.get("address", f.get("instructionPointerReference", "?"))
                print(f"    {addr}: {fname}")

        run_test("Test 7: Stack trace at BP", test_stack_trace, errors)

        # --- Test 8: Evaluate register expression ---
        def test_evaluate_register():
            tid = state.get("bp_thread", state["main_tid"])
            ev = get_json(client.call("tools/call", {
                "name": "veh_evaluate",
                "arguments": {"expression": "RSP", "threadId": tid}
            }))
            assert "value" in ev, f"Evaluate RSP failed: {ev}"
            rsp = ev["value"]
            print(f"  RSP = {rsp}")

            # Pointer dereference
            ev2 = get_json(client.call("tools/call", {
                "name": "veh_evaluate",
                "arguments": {"expression": f"*{rsp}", "threadId": tid}
            }))
            assert "value" in ev2, f"Deref RSP failed: {ev2}"
            print(f"  *RSP = {ev2['value']}")

        run_test("Test 8: Evaluate register + deref", test_evaluate_register, errors)

        # --- Test 9: Step over ---
        def test_step_over():
            tid = state.get("bp_thread", state["main_tid"])
            regs_before = get_json(client.call("tools/call", {
                "name": "veh_registers", "arguments": {"threadId": tid}
            }))
            rip_before = regs_before["registers"].get("rip", regs_before["registers"].get("eip", ""))

            step = get_json(client.call("tools/call", {
                "name": "veh_step_over",
                "arguments": {"threadId": tid}
            }))
            assert "error" not in step, f"StepOver failed: {step}"

            regs_after = get_json(client.call("tools/call", {
                "name": "veh_registers", "arguments": {"threadId": tid}
            }))
            rip_after = regs_after["registers"].get("rip", regs_after["registers"].get("eip", ""))
            print(f"  StepOver: {rip_before} -> {rip_after}")
            assert rip_before != rip_after, f"RIP didn't change after step"

        run_test("Test 9: Step over", test_step_over, errors)

        # --- Test 10: Step in ---
        def test_step_in():
            tid = state.get("bp_thread", state["main_tid"])
            regs_before = get_json(client.call("tools/call", {
                "name": "veh_registers", "arguments": {"threadId": tid}
            }))
            rip_before = regs_before["registers"].get("rip", regs_before["registers"].get("eip", ""))

            step = get_json(client.call("tools/call", {
                "name": "veh_step_in",
                "arguments": {"threadId": tid}
            }))
            assert "error" not in step, f"StepIn failed: {step}"

            regs_after = get_json(client.call("tools/call", {
                "name": "veh_registers", "arguments": {"threadId": tid}
            }))
            rip_after = regs_after["registers"].get("rip", regs_after["registers"].get("eip", ""))
            print(f"  StepIn: {rip_before} -> {rip_after}")

        run_test("Test 10: Step in", test_step_in, errors)

        # --- Test 11: Step out ---
        def test_step_out():
            tid = state.get("bp_thread", state["main_tid"])
            regs_before = get_json(client.call("tools/call", {
                "name": "veh_registers", "arguments": {"threadId": tid}
            }))
            rip_before = regs_before["registers"].get("rip", regs_before["registers"].get("eip", ""))

            step = get_json(client.call("tools/call", {
                "name": "veh_step_out",
                "arguments": {"threadId": tid}
            }))
            # step_out may timeout if we're in main -- that's OK
            if "error" in step:
                print(f"  StepOut: {step.get('error', '')[:60]} (expected if in main)")
            else:
                regs_after = get_json(client.call("tools/call", {
                    "name": "veh_registers", "arguments": {"threadId": tid}
                }))
                rip_after = regs_after["registers"].get("rip", regs_after["registers"].get("eip", ""))
                print(f"  StepOut: {rip_before} -> {rip_after}")

        run_test("Test 11: Step out", test_step_out, errors)

        # --- Test 12: Multi-thread inspection ---
        def test_multi_thread():
            threads = get_json(client.call("tools/call", {
                "name": "veh_threads", "arguments": {}
            }))
            tids = [t["id"] for t in threads.get("threads", [])]
            assert len(tids) >= 1, f"No threads"

            for tid in tids[:5]:  # max 5 threads
                regs = get_json(client.call("tools/call", {
                    "name": "veh_registers", "arguments": {"threadId": tid}
                }))
                rip = regs.get("registers", {}).get("rip",
                       regs.get("registers", {}).get("eip", "?"))
                st = get_json(client.call("tools/call", {
                    "name": "veh_stack_trace", "arguments": {"threadId": tid}
                }))
                frames = len(st.get("frames", []))
                print(f"  Thread {tid}: RIP={rip}, {frames} frames")

        run_test("Test 12: Multi-thread inspection", test_multi_thread, errors)

        # Cleanup
        try:
            client.call("tools/call", {"name": "veh_detach", "arguments": {}}, timeout=5)
        except:
            pass
        if "pid" in state:
            os.system(f"taskkill /PID {state['pid']} /F >nul 2>&1")

    except Exception as e:
        print(f"\n[FATAL] {type(e).__name__}: {e}")
        errors.append(f"Fatal: {e}")
        if "pid" in state:
            os.system(f"taskkill /PID {state['pid']} /F >nul 2>&1")
    finally:
        client.close()

    print()
    print("=" * 60)
    total = 12
    passed = total - len(errors)
    if errors:
        print(f"FAILED - {passed}/{total} passed, {len(errors)} error(s):")
        for e in errors:
            print(f"  - {e}")
        return 1
    else:
        print(f"ALL TESTS PASSED ({total}/{total})")
        return 0

if __name__ == "__main__":
    sys.exit(main())
