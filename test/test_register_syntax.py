"""Test: evaluate with $rax syntax (GDB/LLDB compat)"""
import subprocess, json, sys, time

ADAPTER = r"D:\News\Hack\Engine\VEHDebugger\for VSCode Extension\build\bin\Release\veh-debug-adapter.exe"
TARGET = r"D:\News\Hack\Engine\VEHDebugger\for VSCode Extension\build\bin\Release\test_target.exe"

proc = subprocess.Popen(
    [ADAPTER], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0
)
seq = [0]

def send(cmd, args=None):
    seq[0] += 1
    msg = {"seq": seq[0], "type": "request", "command": cmd}
    if args: msg["arguments"] = args
    body = json.dumps(msg).encode()
    proc.stdin.write(f"Content-Length: {len(body)}\r\n\r\n".encode() + body)
    proc.stdin.flush()

def recv(timeout=5):
    buf = b""
    start = time.time()
    while time.time() - start < timeout:
        ch = proc.stdout.read(1)
        if not ch: time.sleep(0.01); continue
        buf += ch
        if buf.endswith(b"\r\n\r\n"):
            for line in buf.decode().split("\r\n"):
                if line.startswith("Content-Length:"):
                    body = proc.stdout.read(int(line.split(":")[1].strip()))
                    return json.loads(body)
            buf = b""
    return None

def recv_until(pred, timeout=15):
    start = time.time()
    while time.time() - start < timeout:
        msg = recv(timeout=2)
        if msg and pred(msg): return msg
    return None

print("=== Register Syntax Test ===")
send("initialize", {"adapterID": "veh", "clientID": "test"})
recv_until(lambda m: m.get("command") == "initialize")

send("launch", {"program": TARGET, "stopOnEntry": True})
recv_until(lambda m: m.get("command") == "launch")
recv_until(lambda m: m.get("event") == "stopped", timeout=5)
send("configurationDone")
recv_until(lambda m: m.get("command") == "configurationDone")
time.sleep(0.3)
print("launched + stopped at entry")

# Test various register syntaxes
tests = ["RAX", "rax", "$rax", "$RAX", "$Rax", "RIP", "$rip", "$RSP", "EAX", "$eax"]
for expr in tests:
    send("evaluate", {"expression": expr, "context": "repl"})
    resp = recv_until(lambda m: m.get("command") == "evaluate" and m.get("type") == "response")
    if resp and resp.get("success"):
        val = resp["body"]["result"]
        print(f"  {expr:8s} -> {val}  OK")
    else:
        msg = resp.get("message", "?") if resp else "TIMEOUT"
        print(f"  {expr:8s} -> FAIL ({msg})")

send("disconnect", {"terminateDebuggee": True})
time.sleep(0.5)
proc.kill()
print("=== Done ===")
