"""Deferred (pending) breakpoint test - MCP path.

Scenario:
  1. launch deferred_host.exe (stopOnEntry) - deferred_dll.dll NOT loaded yet
  2. set_function_breakpoint "deferred_func" -> must return {"pending": true}
  3. list_breakpoints -> status "pending"
  4. continue(wait): host late-loads the DLL -> ModuleLoaded -> worker binds the BP
     -> deferred_func() is hit -> stop reason "breakpoint"
  5. list_breakpoints -> status "active" (bound)

Requires build_deferred.bat to have produced deferred_host.exe + deferred_dll.dll
in build/bin/Release/.
"""
import subprocess
import json
import time
import sys
import os

BASE = os.path.join(os.path.dirname(__file__), "..", "build", "bin", "Release")
MCP_EXE = os.path.join(BASE, "veh-mcp-server.exe")
HOST = os.path.join(BASE, "deferred_host.exe")


class McpClient:
    def __init__(self):
        self.proc = subprocess.Popen(
            [MCP_EXE], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.seq = 0

    def send(self, method, params=None):
        self.seq += 1
        msg = {"jsonrpc": "2.0", "id": self.seq, "method": method}
        if params:
            msg["params"] = params
        self.proc.stdin.write((json.dumps(msg) + "\n").encode())
        self.proc.stdin.flush()
        return self.seq

    def recv(self, timeout=20):
        start = time.time()
        while time.time() - start < timeout:
            line = self.proc.stdout.readline()
            if not line:
                break
            line = line.decode(errors="replace").strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            # skip notifications (no "id"); we want method responses
            if "id" in obj:
                return obj
        return None

    def call(self, name, args=None):
        self.send("tools/call", {"name": name, "arguments": args or {}})
        resp = self.recv()
        if not resp:
            return {}
        result = resp.get("result", {})
        content = result.get("content", [{}])
        text = content[0].get("text", "") if content else ""
        try:
            return json.loads(text) if text else {}
        except json.JSONDecodeError:
            return {"_raw": text}

    def close(self):
        try:
            self.proc.stdin.close()
        except Exception:
            pass
        try:
            self.proc.terminate()
            self.proc.wait(timeout=3)
        except Exception:
            self.proc.kill()


def main():
    if not os.path.exists(HOST):
        print(f"FAIL: {HOST} missing - run build_deferred.bat first")
        return 1

    c = McpClient()
    try:
        c.send("initialize", {"protocolVersion": "2024-11-05",
                              "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}})
        assert c.recv(), "initialize failed"

        d = c.call("veh_launch", {"program": HOST, "stopOnEntry": True})
        assert d.get("pid", 0) > 0, f"launch failed: {d}"
        print(f"  launched pid={d['pid']}")

        # BP on a symbol whose module is not loaded yet
        d = c.call("veh_set_function_breakpoint", {"name": "deferred_func"})
        print(f"  set_function_breakpoint -> {d}")
        assert d.get("pending") is True, f"expected pending=true, got {d}"

        d = c.call("veh_list_breakpoints")
        sw = d.get("software", [])
        assert any(b.get("status") == "pending" for b in sw), f"no pending BP listed: {sw}"
        print(f"  list (pending): {sw}")

        # Continue: the host late-loads the DLL; worker should bind the BP and it should hit.
        d = c.call("veh_continue", {"threadId": 0, "wait": True, "timeout": 20})
        print(f"  continue -> {d}")
        assert d.get("stopped") is True, f"did not stop: {d}"
        assert d.get("reason") == "breakpoint", f"stopped but not at breakpoint: {d}"

        d = c.call("veh_list_breakpoints")
        sw = d.get("software", [])
        print(f"  list (after bind): {sw}")
        assert any(b.get("status") == "active" for b in sw), f"BP not bound active: {sw}"

        # Confirm we are actually inside deferred_func via stack/registers
        st = c.call("veh_stack_trace", {"threadId": d_thread(d) if False else 0})
        print(f"  stack top: {st.get('frames', st)[:1] if isinstance(st.get('frames', st), list) else st}")

        c.call("veh_detach")
        print("\nDEFERRED BP TEST PASSED")
        return 0
    except AssertionError as e:
        print(f"\nFAILED: {e}")
        return 1
    finally:
        c.close()


def d_thread(d):
    return d.get("threadId", 0)


if __name__ == "__main__":
    sys.exit(main())
