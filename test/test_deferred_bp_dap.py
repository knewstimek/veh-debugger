"""Deferred (pending) breakpoint test - DAP path.

  1. launch deferred_host.exe (stopOnEntry); deferred_dll.dll not loaded yet
  2. setBreakpoints on deferred_dll.cpp:3 -> verified=false (pending, module not loaded)
  3. configurationDone + continue
  4. host late-loads the DLL -> ModuleLoaded -> worker re-resolves -> sends
     'breakpoint' event (reason=changed, verified=true), then BP hits -> 'stopped'
"""
import subprocess, json, sys, time, os

BASE = os.path.join(os.path.dirname(__file__), "..", "build", "bin", "Release")
ADAPTER = os.path.join(BASE, "veh-debug-adapter.exe")
HOST = os.path.join(BASE, "deferred_host.exe")
SCRATCH = os.path.join(os.environ.get("TEMP", ""), "claude",
                       "D--News-Hack-Engine-VEHDebugger-for-VSCode-Extension")
# deferred_dll.cpp absolute path (as embedded in the PDB at compile time)
SOURCE = None
for root, _dirs, files in os.walk(SCRATCH):
    if "deferred_dll.cpp" in files:
        SOURCE = os.path.join(root, "deferred_dll.cpp")
        break

proc = subprocess.Popen([ADAPTER], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, bufsize=0)
seq = [0]

def send(cmd, args=None):
    seq[0] += 1
    msg = {"seq": seq[0], "type": "request", "command": cmd}
    if args:
        msg["arguments"] = args
    body = json.dumps(msg).encode()
    proc.stdin.write(f"Content-Length: {len(body)}\r\n\r\n".encode() + body)
    proc.stdin.flush()

def recv(timeout=5):
    buf = b""
    start = time.time()
    while time.time() - start < timeout:
        ch = proc.stdout.read(1)
        if not ch:
            time.sleep(0.01); continue
        buf += ch
        if buf.endswith(b"\r\n\r\n"):
            for line in buf.decode(errors="replace").split("\r\n"):
                if line.startswith("Content-Length:"):
                    n = int(line.split(":")[1].strip())
                    return json.loads(proc.stdout.read(n))
            buf = b""
    return None

def recv_until(pred, timeout=20):
    start = time.time()
    seen = []
    while time.time() - start < timeout:
        m = recv(timeout=2)
        if m is None:
            continue
        seen.append(m)
        if pred(m):
            return m, seen
    return None, seen

def fail(msg):
    print(f"\nFAILED: {msg}")
    proc.kill()
    sys.exit(1)

if SOURCE is None or not os.path.exists(HOST):
    fail(f"missing prerequisites (SOURCE={SOURCE}, HOST exists={os.path.exists(HOST)})")
print(f"  source = {SOURCE}")

send("initialize", {"adapterID": "veh", "clientID": "test"})
recv_until(lambda m: m.get("command") == "initialize" and m.get("type") == "response")

send("launch", {"program": HOST, "stopOnEntry": True})
launch_ok = initialized = False
for _ in range(15):
    m = recv(timeout=3)
    if not m:
        continue
    if m.get("type") == "response" and m.get("command") == "launch":
        launch_ok = m.get("success", False)
    if m.get("event") == "initialized":
        initialized = True
    if launch_ok and initialized:
        break
if not launch_ok:
    fail("launch failed")
print("  launched")

# Source BP on not-yet-loaded module -> expect verified=false (pending)
send("setBreakpoints", {"source": {"path": SOURCE}, "breakpoints": [{"line": 3}]})
resp, _ = recv_until(lambda m: m.get("command") == "setBreakpoints" and m.get("type") == "response")
bps = resp["body"]["breakpoints"]
print(f"  setBreakpoints -> {bps}")
if bps[0].get("verified") is not False:
    fail(f"expected verified=false (pending), got {bps[0]}")
pending_id = bps[0]["id"]
print(f"  pending bp id={pending_id}")

send("configurationDone")
recv_until(lambda m: m.get("command") == "configurationDone" and m.get("type") == "response", timeout=5)

# continue main; host will late-load the DLL during this
send("continue", {"threadId": 0})

# Expect: 'breakpoint' changed event (verified=true) AND a 'stopped' (reason breakpoint)
got_changed = False
got_stopped = False
start = time.time()
while time.time() - start < 25 and not (got_changed and got_stopped):
    m = recv(timeout=3)
    if not m:
        continue
    if m.get("event") == "breakpoint":
        b = m.get("body", {}).get("breakpoint", {})
        print(f"  >> breakpoint event: reason={m['body'].get('reason')} verified={b.get('verified')} id={b.get('id')}")
        if b.get("verified") is True and b.get("id") == pending_id:
            got_changed = True
    if m.get("event") == "stopped":
        print(f"  >> stopped event: reason={m['body'].get('reason')}")
        if m["body"].get("reason") == "breakpoint":
            got_stopped = True

if not got_changed:
    fail("did not receive 'breakpoint' changed event (verified=true) for deferred BP")
if not got_stopped:
    fail("deferred BP was reported bound but never hit (no stopped/breakpoint)")

print("\nDEFERRED BP (DAP) TEST PASSED")
send("disconnect")
time.sleep(0.5)
proc.kill()
