"""Test edge cases for setBreakpoints on PDB-less binary."""
import subprocess, json, sys, time, os

ADAPTER = os.path.join(os.path.dirname(__file__), "..", "build", "bin", "Release", "veh-debug-adapter.exe")
TARGET = os.path.join(os.path.dirname(__file__), "challenges", "crackme", "crackme_x64.exe")

proc = subprocess.Popen(
    [ADAPTER, "--log-level=debug"],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    bufsize=0
)

seq = [0]

def send(cmd, args=None):
    seq[0] += 1
    msg = {"seq": seq[0], "type": "request", "command": cmd}
    if args: msg["arguments"] = args
    body = json.dumps(msg).encode()
    header = f"Content-Length: {len(body)}\r\n\r\n".encode()
    proc.stdin.write(header + body)
    proc.stdin.flush()

def recv(timeout=5):
    buf = b""
    start = time.time()
    while time.time() - start < timeout:
        ch = proc.stdout.read(1)
        if not ch:
            time.sleep(0.01)
            continue
        buf += ch
        if buf.endswith(b"\r\n\r\n"):
            for line in buf.decode().split("\r\n"):
                if line.startswith("Content-Length:"):
                    length = int(line.split(":")[1].strip())
                    body = proc.stdout.read(length)
                    return json.loads(body)
            buf = b""
    return None

def recv_until(predicate, timeout=15):
    msgs = []
    start = time.time()
    while time.time() - start < timeout:
        msg = recv(timeout=2)
        if msg is None: continue
        msgs.append(msg)
        if predicate(msg):
            return msg, msgs
    return None, msgs

print("=== Source BP Edge Case Test ===")

send("initialize", {"adapterID": "veh", "clientID": "test"})
recv_until(lambda m: m.get("command") == "initialize" and m.get("type") == "response")
print("1. initialized")

send("launch", {"program": TARGET, "stopOnEntry": True})
for _ in range(15):
    msg = recv(timeout=3)
    if msg and msg.get("type") == "response" and msg.get("command") == "launch":
        break
print("2. launched")

tests = [
    ("empty source path", {"source": {"path": ""}, "breakpoints": [{"line": 1}]}),
    ("very long source path", {"source": {"path": "C:\\" + "x" * 600 + "\\main.cpp"}, "breakpoints": [{"line": 1}]}),
    ("no source field", {"breakpoints": [{"line": 1}]}),
    ("source with null-like", {"source": {"path": "\\x00\\x00"}, "breakpoints": [{"line": 1}]}),
    ("line 0", {"source": {"path": "C:\\test.cpp"}, "breakpoints": [{"line": 0}]}),
    ("negative line", {"source": {"path": "C:\\test.cpp"}, "breakpoints": [{"line": -1}]}),
    ("many breakpoints", {"source": {"path": "C:\\test.cpp"}, "breakpoints": [{"line": i} for i in range(1, 51)]}),
]

for name, args in tests:
    print(f"\n--- Test: {name} ---")
    send("setBreakpoints", args)
    bp_resp, all_msgs = recv_until(
        lambda m: m.get("command") == "setBreakpoints" and m.get("type") == "response",
        timeout=10
    )
    if bp_resp is None:
        print(f"   FAIL: No response!")
        if proc.poll() is not None:
            print(f"   ADAPTER CRASHED! Exit code: {proc.returncode}")
            stderr = proc.stderr.read().decode(errors='replace')
            if stderr: print(f"   stderr: {stderr[:300]}")
            sys.exit(1)
        else:
            print("   Adapter alive but not responding")
    else:
        bps = bp_resp.get("body", {}).get("breakpoints", [])
        n_verified = sum(1 for bp in bps if bp.get("verified"))
        n_unverified = sum(1 for bp in bps if not bp.get("verified"))
        print(f"   OK: {n_verified} verified, {n_unverified} unverified")
        if bps and bps[0].get("message"):
            print(f"   msg: {bps[0]['message']}")

# Verify adapter still works
print("\n--- Final check: adapter health ---")
send("threads")
t, _ = recv_until(lambda m: m.get("command") == "threads", timeout=5)
if t and t.get("success"):
    print("OK: Adapter still functional")
else:
    print(f"FAIL: threads: {t}")

send("disconnect", {"terminateDebuggee": True})
time.sleep(1)
if proc.poll() is None: proc.kill()
print("\n=== Edge Case Test Complete ===")
