"""Agent-feedback features test (v1.1.11 candidate).

Covers the 3 MCP-side additions:
  #1 veh_launch env parameter (smoke: accepts env, launch succeeds)
  #2 veh_read_pointer_chain (fully controlled via allocate + write)
  #4 veh_set_data_breakpoint condition/hitCondition ('value' token)

Run: py -3 test/test_agent_feedback_features.py
"""
import subprocess, json, time, sys, os, re
from build_paths import RELEASE
from bounded_pipe import bound

MCP_EXE = os.path.join(RELEASE, "veh-mcp-server.exe")
TARGET  = os.path.join(RELEASE, "test_target.exe")

passed = failed = 0
LAUNCHED = set()  # targets this file started; other test files may run concurrently

def kill_launched():
    for pid in list(LAUNCHED):
        os.system(f"taskkill /PID {pid} /F >nul 2>&1")
    LAUNCHED.clear()
errors = []

class McpClient:
    def __init__(self):
        self.proc = subprocess.Popen([MCP_EXE], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        bound(self.proc)
        self.seq = 0
    def send(self, method, params=None):
        self.seq += 1
        msg = {"jsonrpc": "2.0", "id": self.seq, "method": method}
        if params: msg["params"] = params
        self.proc.stdin.write((json.dumps(msg) + "\n").encode()); self.proc.stdin.flush()
        return self.seq
    def recv(self, timeout=15):
        start = time.time()
        while time.time() - start < timeout:
            line = self.proc.stdout.readline()
            if line:
                line = line.decode(errors="replace").strip()
                if not line: continue
                try: msg = json.loads(line)
                except json.JSONDecodeError: continue
                if "id" not in msg: continue  # skip notifications
                return msg
        return None
    def call(self, name, args=None, timeout=15):
        self.send("tools/call", {"name": name, "arguments": args or {}})
        result = get_content(self.recv(timeout=timeout))
        if name == "veh_launch" and isinstance(result, dict) and result.get("pid"):
            LAUNCHED.add(result["pid"])
        return result
    def initialize(self):
        self.send("initialize", {"protocolVersion": "2024-11-05",
                                 "clientInfo": {"name": "t", "version": "1"}, "capabilities": {}})
        return self.recv()
    def close(self):
        for f in (lambda: self.proc.stdin.close(), self.proc.terminate,
                  lambda: self.proc.wait(timeout=3)):
            try: f()
            except: pass

def get_content(resp):
    try: return json.loads(resp["result"]["content"][0]["text"])
    except: return resp

def check(name, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1; print(f"  PASS: {name}")
    else:
        failed += 1; m = f"  FAIL: {name}" + (f" -- {detail}" if detail else "")
        print(m); errors.append(m)

def le_hex(val, nbytes):
    return " ".join(f"{(val >> (8*i)) & 0xff:02x}" for i in range(nbytes))

def module_base(c, name_sub):
    mods = c.call("veh_modules")
    for m in mods.get("modules", []):
        if name_sub in m.get("name", "").lower():
            return int(m["baseAddress"], 16)
    return None


# ---------------- #1 env smoke ----------------
def test_env():
    print("\n=== #1 veh_launch env ===")
    c = McpClient()
    try:
        c.initialize()
        r = c.call("veh_launch", {"program": TARGET, "stopOnEntry": True,
                                  "env": {"VEHDBG_TEST": "HELLO123", "FOO": "BAR"}})
        print(f"  launch: {r}")
        check("launch with env succeeds", r.get("success") and r.get("pid"), str(r))
        # array form
        c.call("veh_detach")
        r = c.call("veh_launch", {"program": TARGET, "stopOnEntry": True,
                                  "env": ["ARR_FORM=1"]})
        check("launch with env array succeeds", r.get("success") and r.get("pid"), str(r))
        c.call("veh_detach")
    finally:
        c.close(); kill_launched()


# ---------------- #2 pointer chain ----------------
def test_pointer_chain():
    print("\n=== #2 veh_read_pointer_chain ===")
    c = McpClient()
    try:
        c.initialize()
        r = c.call("veh_launch", {"program": TARGET, "stopOnEntry": True})
        check("launch", r.get("success"), str(r))

        a = c.call("veh_allocate_memory", {"size": 256, "protection": "rw"})
        R = int(a["address"], 16)
        print(f"  region R = 0x{R:X}")

        # R+0x00 -> pointer to R+0x40 ; R+0x48 -> 0xCAFEBABE (dword)
        c.call("veh_write_memory", {"address": f"0x{R:X}",      "data": le_hex(R + 0x40, 8)})
        c.call("veh_write_memory", {"address": f"0x{R+0x48:X}", "data": le_hex(0xCAFEBABE, 4)})

        # chain A: deref once -> R+0x40
        a1 = c.call("veh_read_pointer_chain", {"base": f"0x{R:X}", "offsets": ["0x0"]})
        print(f"  A: {a1}")
        check("chainA resolves to R+0x40", int(a1.get("resolved", "0"), 16) == R + 0x40, str(a1))

        # chain B: deref R+0 -> R+0x40, then +0x8 NO deref -> R+0x48, read dword
        b = c.call("veh_read_pointer_chain",
                   {"base": f"0x{R:X}", "offsets": ["0x0", "0x8"], "derefFinal": False, "size": 4})
        print(f"  B: {b}")
        check("chainB resolved == R+0x48", int(b.get("resolved", "0"), 16) == R + 0x48, str(b))
        check("chainB value == 0xCAFEBABE", int(b.get("value", "0"), 16) == 0xCAFEBABE, str(b))

        # chain C: full deref R+0 -> R+0x40, then +0x8 deref -> *(R+0x48)=0xCAFEBABE
        cc = c.call("veh_read_pointer_chain",
                    {"base": f"0x{R:X}", "offsets": ["0x0", "0x8"], "derefFinal": True})
        print(f"  C: {cc}")
        check("chainC resolved == 0xCAFEBABE", int(cc.get("resolved", "0"), 16) == 0xCAFEBABE, str(cc))

        # negative: unmapped deref -> error + failedStep 0
        n = c.call("veh_read_pointer_chain", {"base": f"0x{R:X}", "offsets": ["0x7FFFFFF0"]})
        print(f"  N: {n}")
        check("bad chain reports error", "error" in n and n.get("failedStep") == 0, str(n))

        c.call("veh_detach")
    finally:
        c.close(); kill_launched()


# ---------------- #4 data bp condition ----------------
def find_g_counter(c, work_func):
    d = c.call("veh_disassemble", {"address": f"0x{work_func:X}", "count": 14})
    insns = d.get("instructions", d.get("disassembly", []))
    print("  WorkFunction disasm:")
    for ins in insns:
        print(f"    {ins}")
    for ins in insns:
        mn = ins.get("mnemonic", "") if isinstance(ins, dict) else str(ins)
        m = re.search(r"dword ptr \[0x([0-9A-Fa-f]+)\]", mn)
        if m:
            return int(m.group(1), 16)
    # fallback: any [0x..]
    for ins in insns:
        mn = ins.get("mnemonic", "") if isinstance(ins, dict) else str(ins)
        m = re.search(r"\[0x([0-9A-Fa-f]+)\]", mn)
        if m:
            return int(m.group(1), 16)
    return None

def test_data_bp_condition():
    print("\n=== #4 veh_set_data_breakpoint condition ===")
    c = McpClient()
    try:
        c.initialize()
        r = c.call("veh_launch", {"program": TARGET, "stopOnEntry": True})
        check("launch", r.get("success"), str(r))
        # Resolve WorkFunction by symbol; its RVA moves between builds.
        probe = c.call("veh_set_function_breakpoint", {"name": "WorkFunction"})
        check("WorkFunction resolved", probe.get("success"), str(probe))
        c.call("veh_remove_breakpoint", {"id": probe.get("id")})
        work_func = int(probe.get("address", "0"), 16)
        g = find_g_counter(c, work_func)
        print(f"  g_counter @ 0x{g:X}" if g else "  g_counter NOT FOUND")
        if not g:
            check("g_counter resolved", False, "could not extract address from disasm")
            c.call("veh_detach"); return

        # g_counter is rewritten several times per loop iteration with trace-target
        # values, so gate on conditions whose truth does not depend on those values.
        never = c.call("veh_set_data_breakpoint", {"address": f"0x{g:X}", "type": "write", "size": 4,
                                                   "condition": "value == 0x7FFFFFF1"})
        check("data bp set", never.get("success"), str(never))
        r = c.call("veh_continue", {"threadId": 0, "wait": True, "timeout": 3})
        check("false condition never stops", r.get("timeout") is True, str(r))
        c.call("veh_remove_data_breakpoint", {"id": never.get("id")})

        always = c.call("veh_set_data_breakpoint", {"address": f"0x{g:X}", "type": "write", "size": 4,
                                                    "condition": "value != 0x7FFFFFF1"})
        r = c.call("veh_continue", {"threadId": 0, "wait": True, "timeout": 5})
        check("true condition stops on the write", r.get("stopped") is True, str(r))
        c.call("veh_remove_data_breakpoint", {"id": always.get("id")})
        c.call("veh_continue", {"threadId": 0})
        c.call("veh_detach")
    finally:
        c.close(); kill_launched()


if __name__ == "__main__":
    print(f"MCP: {MCP_EXE}\nTARGET: {TARGET}")
    for fn in (test_env, test_pointer_chain, test_data_bp_condition):
        try: fn()
        except Exception as e:
            failed += 1; errors.append(f"EXCEPTION {fn.__name__}: {e}")
            print(f"  EXCEPTION in {fn.__name__}: {e}")
            kill_launched()
    print(f"\n{'='*50}\nResults: {passed} passed, {failed} failed")
    for e in errors: print(" ", e)
    sys.exit(0 if failed == 0 else 1)
