"""Agent-feedback features test (v1.1.11 candidate).

Covers the 3 MCP-side additions:
  #1 veh_launch env parameter (smoke: accepts env, launch succeeds)
  #2 veh_read_pointer_chain (fully controlled via allocate + write)
  #4 veh_set_data_breakpoint condition/hitCondition ('value' token)

Run: py -3 test/test_agent_feedback_features.py
"""
import subprocess, json, time, sys, os, re

MCP_EXE = os.path.join(os.path.dirname(__file__), "..", "build", "bin", "Release", "veh-mcp-server.exe")
TARGET  = os.path.join(os.path.dirname(__file__), "..", "build", "bin", "Release", "test_target.exe")

passed = failed = 0
errors = []

class McpClient:
    def __init__(self):
        self.proc = subprocess.Popen([MCP_EXE], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
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
        return get_content(self.recv(timeout=timeout))
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
        c.close(); os.system("taskkill /IM test_target.exe /F >nul 2>&1")


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
        c.close(); os.system("taskkill /IM test_target.exe /F >nul 2>&1")


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
        base = module_base(c, "test_target")
        work_func = base + 0x1000
        g = find_g_counter(c, work_func)
        print(f"  g_counter @ 0x{g:X}" if g else "  g_counter NOT FOUND")
        if not g:
            check("g_counter resolved", False, "could not extract address from disasm")
            c.call("veh_detach"); return

        # data write BP: stop only when the stored value == 5
        bp = c.call("veh_set_data_breakpoint",
                    {"address": f"0x{g:X}", "type": "write", "size": 4, "condition": "value == 5"})
        print(f"  data bp: {bp}")
        check("data bp set", bp.get("success"), str(bp))

        # resume; counter increments ~1/sec, must stop at value 5 (~5s)
        c.call("veh_continue", {"threadId": 0})
        time.sleep(8)

        val = c.call("veh_read_memory", {"address": f"0x{g:X}", "size": 4})
        raw = val.get("hex", "").split()
        cur = int("".join(reversed(raw[:4])), 16) if len(raw) >= 4 else -1
        print(f"  g_counter after condition stop = {cur}")
        check("condition 'value==5' stopped at 5", cur == 5, f"got {cur} (expected 5)")

        c.call("veh_remove_data_breakpoint", {"id": bp.get("id")})
        c.call("veh_continue", {"threadId": 0})
        c.call("veh_detach")
    finally:
        c.close(); os.system("taskkill /IM test_target.exe /F >nul 2>&1")


if __name__ == "__main__":
    print(f"MCP: {MCP_EXE}\nTARGET: {TARGET}")
    for fn in (test_env, test_pointer_chain, test_data_bp_condition):
        try: fn()
        except Exception as e:
            failed += 1; errors.append(f"EXCEPTION {fn.__name__}: {e}")
            print(f"  EXCEPTION in {fn.__name__}: {e}")
            os.system("taskkill /IM test_target.exe /F >nul 2>&1")
    print(f"\n{'='*50}\nResults: {passed} passed, {failed} failed")
    for e in errors: print(" ", e)
    sys.exit(0 if failed == 0 else 1)
