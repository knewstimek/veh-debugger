"""MCP StepOver CALL skip test.

Strategy:
1. Launch test_target with stopOnEntry=true (CREATE_SUSPENDED)
2. Find test_target module base + locate CALL instructions
3. Set BP at a CALL instruction BEFORE resuming
4. Continue -> BP hit on first loop iteration
5. Step-over the CALL -> verify we skip over it
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

    def recv(self, timeout=10):
        """Read one JSON-RPC message. Returns responses and notifications alike."""
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
        """Read messages until we find the response matching req_id. Skip notifications."""
        start = time.time()
        while time.time() - start < timeout:
            msg = self.recv(timeout=max(0.5, timeout - (time.time() - start)))
            if msg is None:
                continue
            # JSON-RPC response has "id" field
            if "id" in msg and msg["id"] == req_id:
                return msg
            # Skip notifications (no "id" or different "id")
            if "method" in msg and "id" not in msg:
                # This is a notification, skip
                continue
        return None

    def call_tool(self, name, args=None):
        req_id = self.send("tools/call", {"name": name, "arguments": args or {}})
        return self.recv_response(req_id)

    def tool_result(self, resp):
        if not resp:
            return None
        result = resp.get("result", {})
        content = result.get("content", [{}])
        text = content[0].get("text", "") if content else ""
        if text:
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return {"raw": text}
        return {}

    def get_rip(self, tid):
        resp = self.call_tool("veh_registers", {"threadId": tid})
        data = self.tool_result(resp)
        if not data:
            return None
        rip = data.get("rip") or data.get("RIP")
        if not rip:
            regs = data.get("registers", {})
            rip = regs.get("rip") or regs.get("RIP")
        return rip

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


def addr_int(s):
    if isinstance(s, int):
        return s
    if isinstance(s, str):
        s = s.strip()
        if s.startswith("0x") or s.startswith("0X"):
            return int(s, 16)
        return int(s)
    return 0


def test_stepover_call_skip():
    print("=== MCP StepOver CALL Skip Test ===\n")
    client = McpClient()

    # 1. Initialize
    req_id = client.send("initialize", {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {"name": "test", "version": "1.0"}
    })
    resp = client.recv_response(req_id)
    assert resp and "result" in resp, f"Initialize failed: {resp}"
    print("1. Initialize OK")

    # 2. Launch with stopOnEntry=true
    resp = client.call_tool("veh_launch", {
        "program": TARGET,
        "stopOnEntry": True
    })
    data = client.tool_result(resp)
    assert data and "error" not in data, f"Launch error: {data}"
    pid = data.get("pid", 0)
    print(f"2. Launched PID={pid}")

    # 3. Get modules (DLL is injected, modules are loaded even though suspended)
    resp = client.call_tool("veh_modules")
    data = client.tool_result(resp)
    modules = data.get("modules", [])
    target_base = None
    for mod in modules:
        name = mod.get("name", "").lower()
        if "test_target" in name:
            target_base = mod.get("baseAddress")
            break
    assert target_base, f"test_target module not found in {[m.get('name') for m in modules[:5]]}"
    print(f"3. test_target base={target_base}")

    # 4. Disassemble code to find CALL instructions
    base_int = addr_int(target_base)
    code_addr = f"0x{base_int + 0x1000:X}"
    resp = client.call_tool("veh_disassemble", {"address": code_addr, "count": 150})
    data = client.tool_result(resp)
    insns = data.get("instructions", [])
    print(f"4. Disassembled {len(insns)} instructions from {code_addr}")

    # Find CALL instructions and their next instruction
    calls = []
    for i, insn in enumerate(insns):
        mn = insn.get("mnemonic", "").lower()
        if mn.startswith("call") and i + 1 < len(insns):
            calls.append({
                "addr": insn.get("address"),
                "next": insns[i + 1].get("address"),
                "operands": insn.get("operands", ""),
                "bytes": insn.get("bytes", ""),
            })

    print(f"   Found {len(calls)} CALL instructions:")
    for c in calls[:8]:
        print(f"     {c['addr']}: call {c['operands']} -> next={c['next']}")

    assert calls, "No CALL instructions found"

    # 5. Set BP at first CALL
    target_call = calls[0]
    call_addr = target_call["addr"]
    expected_next = target_call["next"]

    resp = client.call_tool("veh_set_breakpoint", {"address": call_addr})
    bp_data = client.tool_result(resp)
    bp_id = bp_data.get("id")
    assert bp_id, f"Failed to set BP: {bp_data}"
    print(f"5. Set BP #{bp_id} at CALL {call_addr}")

    # 6. Continue (this resumes from CREATE_SUSPENDED + runs to BP)
    resp = client.call_tool("veh_continue", {"threadId": 0})
    print(f"6. Continue -> waiting for BP hit...")

    # 7. Get threads and poll for BP hit
    time.sleep(0.5)  # Give time for process to start and hit BP

    resp = client.call_tool("veh_threads")
    td = client.tool_result(resp)
    threads = td.get("threads", [])

    # Find which thread hit the BP
    tid = 0
    rip_at_bp = None
    for attempt in range(15):
        for t in threads:
            t_id = t["id"]
            rip = client.get_rip(t_id)
            if rip and addr_int(rip) == addr_int(call_addr):
                tid = t_id
                rip_at_bp = rip
                break
        if tid:
            break
        time.sleep(0.5)
        # Refresh thread list
        resp = client.call_tool("veh_threads")
        td = client.tool_result(resp)
        threads = td.get("threads", [])

    if not tid:
        print(f"   BP not hit after 7.5s")
        # Show all thread RIPs for debug
        for t in threads:
            r = client.get_rip(t["id"])
            print(f"   thread {t['id']}: RIP={r}")
        client.call_tool("veh_detach")
        client.close()
        return False

    print(f"7. BP hit! thread={tid}, RIP={rip_at_bp}")

    # 8. Remove the user BP (so only our temp BP will be active)
    client.call_tool("veh_remove_breakpoint", {"id": bp_id})
    print(f"8. Removed user BP #{bp_id}")

    # 8b. Debug: verify the CALL is visible at current RIP
    resp = client.call_tool("veh_disassemble", {"address": rip_at_bp, "count": 3})
    dbg = client.tool_result(resp)
    dbg_insns = dbg.get("instructions", [])
    print(f"8b. Disasm at BP ({rip_at_bp}):")
    for di in dbg_insns:
        print(f"    {di.get('address')}: {di.get('mnemonic')} {di.get('operands','')}")

    # Also read raw memory at BP
    resp = client.call_tool("veh_read_memory", {"address": rip_at_bp, "size": 16})
    mem = client.tool_result(resp)
    print(f"    Raw memory: {mem.get('hex', mem.get('data', ''))[:60]}")

    # 9. StepOver the CALL
    print(f"\n9. === StepOver the CALL at {call_addr} ===")
    print(f"   Expected to land at: {expected_next}")

    resp = client.call_tool("veh_step_over", {"threadId": tid})
    step_data = client.tool_result(resp)
    skipped = step_data.get("skippedCall", False)
    print(f"   StepOver: success={step_data.get('success')} skippedCall={skipped}")

    # Wait for temp BP to be hit (CALL returns)
    time.sleep(1.0)

    # 10. Check where we landed
    rip_after = client.get_rip(tid)
    print(f"\n10. Results:")
    print(f"    CALL addr:  {call_addr}")
    print(f"    Expected:   {expected_next}")
    print(f"    Actual RIP: {rip_after}")
    print(f"    skippedCall: {skipped}")

    passed = False
    if rip_after and expected_next:
        actual = addr_int(rip_after)
        expected = addr_int(expected_next)
        if actual == expected:
            print(f"    >>> PASS: Landed exactly at next instruction!")
            passed = True
        else:
            # Show stack to see if we entered the callee
            resp = client.call_tool("veh_stack_trace", {"threadId": tid, "maxFrames": 5})
            st = client.tool_result(resp)
            frames = st.get("frames", []) if st else []
            print(f"    Stack ({len(frames)} frames):")
            for f in frames[:5]:
                print(f"      {f.get('address')} {f.get('function', '?')}")
            if skipped:
                print(f"    >>> PARTIAL: CALL detected but landed at wrong addr")
            else:
                print(f"    >>> FAIL: CALL not detected or step-over broken")
    elif skipped:
        print(f"    >>> CALL was detected (skippedCall=true)")
        if rip_after:
            print(f"    RIP moved to {rip_after}")
            passed = True
        else:
            print(f"    WARNING: could not read RIP after step")

    # 11. Bonus: do more step-overs to verify consecutive behavior
    print(f"\n11. Consecutive step-overs:")
    for i in range(5):
        rip_before = client.get_rip(tid)
        resp = client.call_tool("veh_step_over", {"threadId": tid})
        sd = client.tool_result(resp)
        time.sleep(0.5)
        rip_after_n = client.get_rip(tid)
        sk = sd.get("skippedCall", False)
        moved = "MOVED" if rip_before != rip_after_n else "SAME"
        print(f"    Step {i+1}: {rip_before} -> {rip_after_n} [{moved}] skippedCall={sk}")

    # Cleanup
    print("\nCleaning up...")
    client.call_tool("veh_detach")
    time.sleep(0.5)
    client.close()

    if passed:
        print("\n=== TEST PASSED ===")
    else:
        print("\n=== TEST FAILED ===")
    return passed


if __name__ == "__main__":
    try:
        success = test_stepover_call_skip()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\nFATAL: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
