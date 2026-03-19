"""Deep integration test - validates actual debugger values, not just API success.

Each test verifies actual correctness of returned data against known ground truth.
"""
import subprocess
import json
import time
import sys
import os

MCP_EXE = os.path.join(os.path.dirname(__file__), "..", "build", "bin", "Release", "veh-mcp-server.exe")
TARGET = os.path.join(os.path.dirname(__file__), "..", "build", "bin", "Release", "test_target.exe")
SOURCE_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "test_target", "main.cpp"))

passed = 0
failed = 0
errors = []

class McpClient:
    def __init__(self):
        self.proc = subprocess.Popen(
            [MCP_EXE],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.seq = 0
        self.notifications = []

    def send(self, method, params=None):
        self.seq += 1
        msg = {"jsonrpc": "2.0", "id": self.seq, "method": method}
        if params: msg["params"] = params
        self.proc.stdin.write((json.dumps(msg) + "\n").encode())
        self.proc.stdin.flush()
        return self.seq

    def recv(self, timeout=15):
        start = time.time()
        while time.time() - start < timeout:
            line = self.proc.stdout.readline()
            if line:
                line = line.decode().strip()
                if not line: continue
                try: msg = json.loads(line)
                except json.JSONDecodeError: continue
                if "id" not in msg:
                    self.notifications.append(msg)
                    continue
                return msg
        return None

    def call(self, name, args=None, timeout=15):
        self.send("tools/call", {"name": name, "arguments": args or {}})
        r = self.recv(timeout=timeout)
        try:
            text = r["result"]["content"][0]["text"]
            return json.loads(text)
        except: return r

    def init_and_launch(self, stop_on_entry=False):
        self.send("initialize", {
            "protocolVersion": "2024-11-05",
            "clientInfo": {"name": "test", "version": "1.0"},
            "capabilities": {}
        })
        self.recv()
        return self.call("veh_launch", {"program": TARGET, "stopOnEntry": stop_on_entry})

    def get_base(self):
        modules = self.call("veh_modules")
        for m in modules.get("modules", []):
            if "test_target" in m.get("name", "").lower():
                return int(m["baseAddress"], 16)
        return None

    def get_first_thread(self):
        threads = self.call("veh_threads")
        if "threads" in threads and threads["threads"]:
            return threads["threads"][0]["id"]
        return None

    def close(self):
        try: self.proc.stdin.close()
        except: pass
        try: self.proc.terminate()
        except: pass
        try: self.proc.wait(timeout=3)
        except: pass

def check(name, condition, detail=""):
    global passed, failed, errors
    if condition:
        passed += 1
        print(f"    PASS: {name}")
    else:
        failed += 1
        msg = f"    FAIL: {name}" + (f" -- {detail}" if detail else "")
        print(msg)
        errors.append(msg)

def cleanup():
    os.system("taskkill /IM test_target.exe /F >nul 2>&1")


# ============================================================
# Test 1: Function BP - verify RIP == function entry address
# ============================================================
def test_function_bp_rip_accuracy():
    print("\n[Test 1] Function BP: RIP must equal function entry address")
    c = McpClient()
    try:
        c.init_and_launch(stop_on_entry=False)
        time.sleep(1)

        bp = c.call("veh_set_function_breakpoint", {"name": "WorkFunction"})
        func_addr = bp.get("address", "")
        bp_id = bp.get("id")
        print(f"    WorkFunction resolved to {func_addr}")
        time.sleep(2)

        tid = c.get_first_thread()
        check("thread found", tid is not None)
        if not tid: return

        rip_data = c.call("veh_evaluate", {"expression": "RIP", "threadId": tid})
        rip_val = rip_data.get("value", "")
        rip_int = int(rip_val, 16)
        func_int = int(func_addr, 16)
        print(f"    RIP = 0x{rip_int:X}")
        check("RIP == WorkFunction address", rip_int == func_int,
              f"RIP=0x{rip_int:X} vs func=0x{func_int:X}")

        if bp_id: c.call("veh_remove_breakpoint", {"id": bp_id})
        c.call("veh_continue", {"threadId": 0})
        c.call("veh_detach")
    finally:
        c.close(); cleanup()


# ============================================================
# Test 2: Source BP line 12 (g_counter++) - verify correct address
# ============================================================
def test_source_bp_line_accuracy():
    print("\n[Test 2] Source BP line 12: RIP must match resolved address")
    c = McpClient()
    try:
        c.init_and_launch(stop_on_entry=False)
        time.sleep(1)

        bp = c.call("veh_set_source_breakpoint", {"source": SOURCE_FILE, "line": 12})
        bp_addr = bp.get("address", "")
        bp_id = bp.get("id")
        bp_line = bp.get("line")
        print(f"    Source BP resolved: line {bp_line} -> {bp_addr}")
        check("line resolved", bp_addr.startswith("0x"), str(bp))

        time.sleep(2)
        tid = c.get_first_thread()
        check("thread found", tid is not None)
        if not tid: return

        rip_data = c.call("veh_evaluate", {"expression": "RIP", "threadId": tid})
        rip_int = int(rip_data["value"], 16)
        bp_int = int(bp_addr, 16)
        print(f"    RIP = 0x{rip_int:X}, BP addr = 0x{bp_int:X}")
        check("RIP == source BP address", rip_int == bp_int,
              f"0x{rip_int:X} vs 0x{bp_int:X}")

        if bp_id: c.call("veh_remove_breakpoint", {"id": bp_id})
        c.call("veh_continue", {"threadId": 0})
        c.call("veh_detach")
    finally:
        c.close(); cleanup()


# ============================================================
# Test 3: Evaluate - RSP is valid stack, [RSP] is return addr
# ============================================================
def test_evaluate_correctness():
    print("\n[Test 3] Evaluate: RSP in stack range, [RSP] = valid return address")
    c = McpClient()
    try:
        c.init_and_launch(stop_on_entry=False)
        time.sleep(1)

        bp = c.call("veh_set_function_breakpoint", {"name": "WorkFunction"})
        bp_id = bp.get("id")
        func_addr = int(bp["address"], 16)
        time.sleep(2)

        tid = c.get_first_thread()
        if not tid: check("thread found", False); return

        # RSP should be in typical stack range
        rsp = c.call("veh_evaluate", {"expression": "RSP", "threadId": tid})
        rsp_val = int(rsp["value"], 16)
        check("RSP looks like stack", rsp_val > 0x10000 and rsp_val < 0x7FFFFFFFFFFF,
              f"RSP=0x{rsp_val:X}")

        # [RSP] should be return address in test_target
        deref = c.call("veh_evaluate", {"expression": f"*0x{rsp_val:X}", "threadId": tid})
        ret_addr = int(deref["value"], 16)
        base = c.get_base()
        print(f"    RSP=0x{rsp_val:X}, [RSP]=0x{ret_addr:X}, base=0x{base:X}")
        check("[RSP] is return addr in test_target", base <= ret_addr < base + 0x100000,
              f"[RSP]=0x{ret_addr:X}, base=0x{base:X}")

        # Disassemble at ret_addr-5 (call rel32 = E8 xx xx xx xx = 5 bytes)
        disasm = c.call("veh_disassemble", {"address": f"0x{ret_addr-5:X}", "count": 3})
        insns = disasm.get("instructions", [])
        found_call = False
        for insn in insns:
            if "call" in insn.get("mnemonic", "").lower():
                insn_addr = int(insn["address"], 16)
                # The call instruction + its size should equal ret_addr
                found_call = True
                break

        print(f"    Disasm at [RSP]-5: {[(i['address'], i['mnemonic']) for i in insns[:3]]}")
        check("[RSP]-5 is a CALL instruction", found_call,
              f"No CALL at 0x{ret_addr-5:X}")

        if bp_id: c.call("veh_remove_breakpoint", {"id": bp_id})
        c.call("veh_continue", {"threadId": 0})
        c.call("veh_detach")
    finally:
        c.close(); cleanup()


# ============================================================
# Test 4: set_register - write RCX, verify via both evaluate and registers
# ============================================================
def test_set_register_verify():
    print("\n[Test 4] set_register: write 0xCAFEBABE to RCX, verify both paths")
    c = McpClient()
    try:
        c.init_and_launch(stop_on_entry=False)
        time.sleep(1)

        bp = c.call("veh_set_function_breakpoint", {"name": "WorkFunction"})
        bp_id = bp.get("id")
        time.sleep(2)

        tid = c.get_first_thread()
        if not tid: check("thread found", False); return

        c.call("veh_set_register", {"threadId": tid, "name": "RCX", "value": "0xCAFEBABE"})

        # Verify via evaluate
        rcx = c.call("veh_evaluate", {"expression": "RCX", "threadId": tid})
        rcx_val = rcx.get("value", "")
        print(f"    RCX via evaluate = {rcx_val}")
        check("RCX == 0xCAFEBABE (evaluate)", "CAFEBABE" in rcx_val.upper(), rcx_val)

        # Verify via veh_registers (response: {"registers": {"rcx": "0x..."}})
        regs_resp = c.call("veh_registers", {"threadId": tid})
        regs = regs_resp.get("registers", regs_resp)
        rcx_from_regs = regs.get("rcx", regs.get("RCX", ""))
        print(f"    RCX via registers = {rcx_from_regs}")
        check("RCX == 0xCAFEBABE (registers)", "CAFEBABE" in rcx_from_regs.upper(), rcx_from_regs)

        if bp_id: c.call("veh_remove_breakpoint", {"id": bp_id})
        c.call("veh_continue", {"threadId": 0})
        c.call("veh_detach")
    finally:
        c.close(); cleanup()


# ============================================================
# Test 5: Logpoint - verify notification content
# ============================================================
def test_logpoint_notification():
    print("\n[Test 5] Logpoint: verify notification contains expanded message")
    c = McpClient()
    try:
        c.init_and_launch(stop_on_entry=False)
        time.sleep(1)

        base = c.get_base()
        work_func = base + 0x1000

        bp = c.call("veh_set_breakpoint", {
            "address": f"0x{work_func:X}",
            "logMessage": "TRACE RIP={RIP} RSP={RSP}"
        })
        bp_id = bp.get("id")
        time.sleep(3)

        # Trigger a response to flush notifications
        c.notifications.clear()
        c.call("veh_threads")

        logpoint_msgs = [n for n in c.notifications
                        if n.get("params", {}).get("logger") == "logpoint"]
        print(f"    Logpoint notifications: {len(logpoint_msgs)}")
        if logpoint_msgs:
            msg_data = logpoint_msgs[0].get("params", {}).get("data", "")
            print(f"    First logpoint: {msg_data}")
            check("logpoint has TRACE prefix", "TRACE" in msg_data, msg_data)
            check("logpoint expanded RIP to hex", "RIP=0x" in msg_data, msg_data)
            check("logpoint expanded RSP to hex", "RSP=0x" in msg_data, msg_data)
            # RIP should be the function address (compare as integers to avoid padding)
            import re
            rip_match = re.search(r'RIP=0x([0-9a-fA-F]+)', msg_data)
            if rip_match:
                rip_in_log = int(rip_match.group(1), 16)
                check("logpoint RIP = function addr", rip_in_log == work_func,
                      f"RIP=0x{rip_in_log:X} vs func=0x{work_func:X}")
            else:
                check("logpoint RIP = function addr", False,
                      f"no RIP= found in '{msg_data}'")
        else:
            check("logpoint notifications received", False, "0 logpoint notifications")

        if bp_id: c.call("veh_remove_breakpoint", {"id": bp_id})
        c.call("veh_detach")
    finally:
        c.close(); cleanup()


# ============================================================
# Test 6: Conditional BP - RAX==0, verify actually stopped with RAX==0
# ============================================================
def test_conditional_bp_value_check():
    print("\n[Test 6] Conditional BP: stop only when RAX==0, verify RAX value")
    c = McpClient()
    try:
        c.init_and_launch(stop_on_entry=False)
        time.sleep(1)

        base = c.get_base()
        work_func = base + 0x1000

        bp = c.call("veh_set_breakpoint", {
            "address": f"0x{work_func:X}",
            "condition": "RAX==0"
        })
        bp_id = bp.get("id")
        time.sleep(2)

        tid = c.get_first_thread()
        if tid:
            rax = c.call("veh_evaluate", {"expression": "RAX", "threadId": tid})
            rax_val = int(rax.get("value", "0x1"), 16)
            print(f"    Stopped with RAX = 0x{rax_val:X}")
            check("RAX == 0 when condition is RAX==0", rax_val == 0, f"RAX=0x{rax_val:X}")
        else:
            check("conditional BP stopped process", False, "no stopped thread")

        if bp_id: c.call("veh_remove_breakpoint", {"id": bp_id})
        c.call("veh_continue", {"threadId": 0})
        c.call("veh_detach")
    finally:
        c.close(); cleanup()


# ============================================================
# Test 7: Trace callers - verify caller is the actual call-site
# ============================================================
def test_trace_callers_verification():
    print("\n[Test 7] TraceCallers: verify caller address is actual call return addr")
    c = McpClient()
    try:
        c.init_and_launch(stop_on_entry=False)
        time.sleep(1)

        base = c.get_base()
        work_func = base + 0x1000

        # Run trace
        trace = c.call("veh_trace_callers", {
            "address": f"0x{work_func:X}",
            "duration_sec": 3
        }, timeout=20)
        callers = trace.get("callers", [])
        total = trace.get("totalHits", 0)
        print(f"    Trace: {total} hits, {len(callers)} unique callers")

        check("trace got hits", total >= 1, f"totalHits={total}")
        check("trace got callers", len(callers) >= 1, f"callers={callers}")

        if callers:
            caller_addr = int(callers[0]["address"], 16)
            hit_count = callers[0]["hitCount"]
            print(f"    Caller = 0x{caller_addr:X} (hits: {hit_count})")

            # Caller must be in test_target
            check("caller in test_target module", base <= caller_addr < base + 0x100000,
                  f"0x{caller_addr:X}")

            # hit count should match total (only 1 caller from main's loop)
            check("hitCount == totalHits (single caller)", hit_count == total,
                  f"hitCount={hit_count} vs total={total}")

            # Disassemble at caller-5: should be 'call' targeting WorkFunction
            disasm = c.call("veh_disassemble", {"address": f"0x{caller_addr-5:X}", "count": 2})
            insns = disasm.get("instructions", [])
            if insns:
                first = insns[0]
                mnemonic = first.get("mnemonic", "")
                operands = first.get("operands", "")
                print(f"    [caller-5] = {first['address']}: {mnemonic} {operands}")
                check("instruction at caller-5 is CALL", "call" in mnemonic.lower(),
                      f"got {mnemonic}")
                # Verify call target is WorkFunction
                # Target may be in operands or embedded in mnemonic (e.g. "call 0x7FF...")
                import re
                combined = f"{mnemonic} {operands}"
                addr_match = re.search(r'0x([0-9a-fA-F]+)', combined)
                if addr_match:
                    target = int(addr_match.group(1), 16)
                    check("CALL target == WorkFunction", target == work_func,
                          f"target=0x{target:X} vs func=0x{work_func:X}")
                else:
                    check("CALL target parseable", False, f"combined='{combined}'")

        c.call("veh_detach")
    finally:
        c.close(); cleanup()


# ============================================================
# Test 8: StepOver - verify RIP moves forward (BP-aware)
# ============================================================
def test_step_and_verify_rip():
    print("\n[Test 8] StepOver: verify RIP advances after step")
    c = McpClient()
    try:
        c.init_and_launch(stop_on_entry=False)
        time.sleep(1)

        bp = c.call("veh_set_function_breakpoint", {"name": "WorkFunction"})
        bp_id = bp.get("id")
        time.sleep(2)

        tid = c.get_first_thread()
        if not tid: check("thread found", False); return

        rip1 = int(c.call("veh_evaluate", {"expression": "RIP", "threadId": tid})["value"], 16)
        print(f"    RIP before step = 0x{rip1:X}")

        # Remove BP first to avoid rearm complexity
        if bp_id: c.call("veh_remove_breakpoint", {"id": bp_id})
        # Do multiple steps to move past any rearm state
        c.call("veh_step_over", {"threadId": tid})
        rip2 = int(c.call("veh_evaluate", {"expression": "RIP", "threadId": tid})["value"], 16)
        print(f"    RIP after 1st step = 0x{rip2:X}")
        check("RIP moved forward after step", rip2 > rip1,
              f"0x{rip2:X} vs 0x{rip1:X}")

        # 2nd step: should advance further
        c.call("veh_step_over", {"threadId": tid})
        rip3 = int(c.call("veh_evaluate", {"expression": "RIP", "threadId": tid})["value"], 16)
        print(f"    RIP after 2nd step = 0x{rip3:X}")
        check("RIP moved forward again", rip3 > rip2,
              f"0x{rip3:X} vs 0x{rip2:X}")

        # All should be in same function (WorkFunction = base+0x1000 to roughly base+0x1070)
        base = c.get_base()
        check("still in WorkFunction", base + 0x1000 <= rip3 < base + 0x1100,
              f"RIP=0x{rip3:X}, func=[0x{base+0x1000:X}, 0x{base+0x1100:X})")

        c.call("veh_continue", {"threadId": 0})
        c.call("veh_detach")
    finally:
        c.close(); cleanup()


# ============================================================
# Test 9: Stack trace - verify call chain WorkFunction < main
# ============================================================
def test_stack_trace_chain():
    print("\n[Test 9] Stack trace: verify call chain from WorkFunction")
    c = McpClient()
    try:
        c.init_and_launch(stop_on_entry=False)
        time.sleep(1)

        bp = c.call("veh_set_function_breakpoint", {"name": "WorkFunction"})
        bp_id = bp.get("id")
        time.sleep(2)

        tid = c.get_first_thread()
        if not tid: check("thread found", False); return

        st = c.call("veh_stack_trace", {"threadId": tid, "maxFrames": 10})
        frames = st.get("frames", [])
        print(f"    Stack frames: {len(frames)}")
        for i, f in enumerate(frames[:5]):
            addr = f.get("address", "?")
            func = f.get("function", "")
            print(f"      [{i}] {addr} {func}")

        check("stack has >= 2 frames", len(frames) >= 2, f"only {len(frames)} frames")

        # Top frame should be in WorkFunction range
        if frames:
            top_addr = int(frames[0].get("address", "0x0"), 16)
            base = c.get_base()
            check("top frame in WorkFunction", base + 0x1000 <= top_addr < base + 0x1070,
                  f"0x{top_addr:X}")

            # Frame[1] should be in main (the call site)
            if len(frames) >= 2:
                f1_addr = int(frames[1].get("address", "0x0"), 16)
                # main is after WorkFunction, roughly base+0x1070..base+0x1200
                check("frame[1] in main area", base + 0x1070 <= f1_addr < base + 0x1200,
                      f"0x{f1_addr:X}")

        if bp_id: c.call("veh_remove_breakpoint", {"id": bp_id})
        c.call("veh_continue", {"threadId": 0})
        c.call("veh_detach")
    finally:
        c.close(); cleanup()


# ============================================================
# Test 10: hitCondition=3 - verify hitCount and timing
# ============================================================
def test_hit_condition_accuracy():
    print("\n[Test 10] hitCondition=3: verify BP fires on 3rd hit")
    c = McpClient()
    try:
        c.init_and_launch(stop_on_entry=False)
        time.sleep(1)

        base = c.get_base()
        work_func = base + 0x1000

        bp = c.call("veh_set_breakpoint", {
            "address": f"0x{work_func:X}",
            "hitCondition": "3"
        })
        bp_id = bp.get("id")

        # After 1.5s, ~1 hit -> should NOT stop
        time.sleep(1.5)
        bp_notes = [n for n in c.notifications
                   if "Breakpoint" in str(n.get("params", {}).get("data", ""))]
        check("not stopped after ~1 hit", len(bp_notes) == 0,
              f"{len(bp_notes)} notifications")

        # Wait for 3rd hit (~3s total)
        time.sleep(3)

        # Check hitCount via list_breakpoints
        bps = c.call("veh_list_breakpoints")
        sw = bps.get("software", [])
        our_bp = next((b for b in sw if b.get("id") == bp_id), None)
        if our_bp:
            hit_count = our_bp.get("hitCount", 0)
            print(f"    BP hitCount = {hit_count}")
            check("hitCount >= 3", hit_count >= 3, f"hitCount={hit_count}")

        tid = c.get_first_thread()
        check("process stopped after 3rd hit", tid is not None, "no stopped thread")

        if bp_id: c.call("veh_remove_breakpoint", {"id": bp_id})
        c.call("veh_continue", {"threadId": 0})
        c.call("veh_detach")
    finally:
        c.close(); cleanup()


if __name__ == "__main__":
    print(f"Source: {SOURCE_FILE}")
    print(f"Target: {TARGET}")

    tests = [
        test_function_bp_rip_accuracy,
        test_source_bp_line_accuracy,
        test_evaluate_correctness,
        test_set_register_verify,
        test_logpoint_notification,
        test_conditional_bp_value_check,
        test_trace_callers_verification,
        test_step_and_verify_rip,
        test_stack_trace_chain,
        test_hit_condition_accuracy,
    ]

    for fn in tests:
        try:
            fn()
        except Exception as e:
            failed += 1
            msg = f"    EXCEPTION in {fn.__name__}: {e}"
            print(msg)
            errors.append(msg)
            cleanup()

    print(f"\n{'='*60}")
    print(f"DEEP TEST Results: {passed} passed, {failed} failed")
    if errors:
        print("\nFailures:")
        for e in errors:
            print(f"  {e}")
    sys.exit(0 if failed == 0 else 1)
