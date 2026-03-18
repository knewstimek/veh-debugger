"""Test: setBreakpoints with source path on a PDB-less binary.
Should gracefully return verified=false, NOT crash."""
import subprocess, json, sys, time

ADAPTER = r"D:\News\Hack\Engine\VEHDebugger\for VSCode Extension\build\bin\Release\veh-debug-adapter.exe"
TARGET = r"D:\News\Hack\Engine\VEHDebugger\for VSCode Extension\test\challenges\crackme\bin\crackme_x64.exe"
FAKE_SOURCE = r"C:\nonexistent\main.cpp"

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

print("=== Source BP on PDB-less binary test ===")

# 1. Initialize
send("initialize", {"adapterID": "veh", "clientID": "test"})
resp, _ = recv_until(lambda m: m.get("command") == "initialize" and m.get("type") == "response")
if not resp:
    print("FAIL: initialize timeout")
    proc.kill()
    sys.exit(1)
print("1. initialized")

# 2. Launch (crackme has no PDB)
send("launch", {"program": TARGET, "stopOnEntry": True})
launch_resp = None
for _ in range(15):
    msg = recv(timeout=3)
    if msg is None: continue
    if msg.get("type") == "response" and msg.get("command") == "launch":
        launch_resp = msg
        break
if not launch_resp or not launch_resp.get("success"):
    print(f"FAIL: launch failed: {launch_resp}")
    proc.kill()
    sys.exit(1)
print("2. launched (PDB-less crackme)")

# 3. Set source breakpoints (should fail gracefully)
print("3. Sending setBreakpoints with source path...")
send("setBreakpoints", {
    "source": {"path": FAKE_SOURCE},
    "breakpoints": [{"line": 10}, {"line": 20}, {"line": 30}]
})

bp_resp, all_msgs = recv_until(
    lambda m: m.get("command") == "setBreakpoints" and m.get("type") == "response",
    timeout=10
)

if bp_resp is None:
    print("   FAIL: No response - connection may have dropped!")
    print(f"   All messages received: {len(all_msgs)}")
    for m in all_msgs:
        print(f"   - {m.get('type','?')}/{m.get('command', m.get('event','?'))}")
    # Check if adapter is still alive
    if proc.poll() is not None:
        print(f"   ADAPTER CRASHED! Exit code: {proc.returncode}")
        stderr = proc.stderr.read().decode(errors='replace')
        if stderr:
            print(f"   stderr: {stderr[:500]}")
    else:
        print("   Adapter still running but not responding")
    proc.kill()
    sys.exit(1)

print(f"   Response received: success={bp_resp.get('success')}")
bps = bp_resp.get("body", {}).get("breakpoints", [])
for i, bp in enumerate(bps):
    print(f"   BP[{i}]: verified={bp.get('verified')} msg={bp.get('message','')}")

all_unverified = all(not bp.get("verified") for bp in bps)
if all_unverified:
    print("   OK: All breakpoints correctly returned as unverified")
else:
    print("   WARNING: Some breakpoints verified on PDB-less binary?")

# 4. ConfigurationDone
send("configurationDone")
recv_until(lambda m: m.get("command") == "configurationDone")
stopped, _ = recv_until(lambda m: m.get("type") == "event" and m.get("event") == "stopped", timeout=5)
print("4. configurationDone + stopped")

# 5. Try setBreakpoints AGAIN to make sure adapter is still functional
print("5. Sending setBreakpoints again (2nd call)...")
send("setBreakpoints", {
    "source": {"path": FAKE_SOURCE},
    "breakpoints": [{"line": 50}]
})
bp_resp2, _ = recv_until(
    lambda m: m.get("command") == "setBreakpoints" and m.get("type") == "response",
    timeout=10
)
if bp_resp2:
    print(f"   2nd response OK: success={bp_resp2.get('success')}")
else:
    print("   FAIL: 2nd setBreakpoints got no response!")
    if proc.poll() is not None:
        print(f"   ADAPTER CRASHED! Exit code: {proc.returncode}")

# 6. Verify other operations still work
print("6. Verifying adapter still functional...")
send("threads")
threads_resp, _ = recv_until(
    lambda m: m.get("command") == "threads" and m.get("type") == "response",
    timeout=5
)
if threads_resp and threads_resp.get("success"):
    print(f"   OK: threads returned {len(threads_resp.get('body',{}).get('threads',[]))} threads")
else:
    print(f"   FAIL: threads failed: {threads_resp}")

# Cleanup
print("\nCleaning up...")
send("disconnect", {"terminateDebuggee": True})
time.sleep(1)
if proc.poll() is None:
    proc.kill()
print("=== Test Complete ===")
