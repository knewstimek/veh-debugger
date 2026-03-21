"""DAP StepIn Test - F11 동작 확인"""
import subprocess, json, sys, time, os

ADAPTER = os.path.join(os.path.dirname(__file__), "..", "build", "bin", "Release", "veh-debug-adapter.exe")
TARGET = os.path.join(os.path.dirname(__file__), "..", "build", "bin", "Release", "test_target.exe")
SOURCE = os.path.join(os.path.dirname(__file__), "..", "test_target", "main.cpp")
LOG = os.path.join(os.path.dirname(__file__), "stepin-test-adapter.log")

proc = subprocess.Popen(
    [ADAPTER, f"--log={LOG}", "--log-level=debug"],
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

print("=== DAP StepIn Test (Launch mode) ===")

# 1. Initialize
send("initialize", {"adapterID": "veh", "clientID": "test"})
resp, _ = recv_until(lambda m: m.get("command") == "initialize" and m.get("type") == "response")
print(f"1. initialize: success={resp['success']}")

# 2. Launch with stopOnEntry
send("launch", {"program": TARGET, "stopOnEntry": True})
launch_resp = None
initialized = False
for _ in range(15):
    msg = recv(timeout=3)
    if msg is None: continue
    if msg.get("type") == "response" and msg.get("command") == "launch":
        launch_resp = msg
    if msg.get("type") == "event" and msg.get("event") == "initialized":
        initialized = True
    if launch_resp and initialized:
        break

if not launch_resp or not launch_resp.get("success"):
    print(f"FAIL: launch failed: {launch_resp}")
    proc.kill()
    sys.exit(1)
print(f"2. launch: success=True")

# 3. Set breakpoint at line 24 (WorkFunction call)
send("setBreakpoints", {
    "source": {"path": SOURCE},
    "breakpoints": [{"line": 24}]
})
bp_resp, _ = recv_until(lambda m: m.get("command") == "setBreakpoints")
if bp_resp:
    bps = bp_resp.get("body", {}).get("breakpoints", [])
    for bp in bps:
        print(f"3. BP line 24: verified={bp.get('verified')} id={bp.get('id')}")

# 4. ConfigurationDone
send("configurationDone")
recv_until(lambda m: m.get("command") == "configurationDone")
print(f"4. configurationDone")

# Wait for stopped (entry)
stopped, _ = recv_until(lambda m: m.get("type") == "event" and m.get("event") == "stopped", timeout=5)
if stopped:
    print(f"   stopped: reason={stopped['body'].get('reason')}")

# 5. Continue to BP
send("continue", {"threadId": 1})
recv_until(lambda m: m.get("command") == "continue")
bp_hit, _ = recv_until(
    lambda m: m.get("type") == "event" and m.get("event") == "stopped"
        and m.get("body",{}).get("reason") == "breakpoint", timeout=10)
if not bp_hit:
    print("FAIL: no breakpoint hit")
    proc.kill()
    sys.exit(1)

tid = bp_hit["body"]["threadId"]
print(f"5. BP hit at line 24! threadId={tid}")

# 6. Stack before
send("stackTrace", {"threadId": tid, "startFrame": 0, "levels": 3})
st, _ = recv_until(lambda m: m.get("command") == "stackTrace")
if st and st["body"]["stackFrames"]:
    f = st["body"]["stackFrames"][0]
    print(f"6. Before: RIP={f.get('instructionPointerReference','?')} line={f.get('line','?')} func={f.get('name','?')}")

# 7. F11 (stepIn) - should step into WorkFunction
print(f"\n7. === F11 (stepIn) threadId={tid} ===")
send("stepIn", {"threadId": tid})
recv_until(lambda m: m.get("command") == "stepIn")

step_stopped, msgs = recv_until(
    lambda m: m.get("type") == "event" and m.get("event") == "stopped", timeout=10)
if step_stopped:
    reason = step_stopped["body"].get("reason")
    step_tid = step_stopped["body"].get("threadId")
    print(f"   stopped: reason={reason} threadId={step_tid}")

    send("stackTrace", {"threadId": step_tid, "startFrame": 0, "levels": 3})
    st2, _ = recv_until(lambda m: m.get("command") == "stackTrace")
    if st2 and st2["body"]["stackFrames"]:
        f2 = st2["body"]["stackFrames"][0]
        func_name = f2.get('name', '?')
        line = f2.get('line', '?')
        print(f"   After stepIn: RIP={f2.get('instructionPointerReference','?')} line={line} func={func_name}")
        if "WorkFunction" in func_name:
            print(f"   >>> SUCCESS: Stepped INTO WorkFunction")
        else:
            print(f"   >>> Stepped to: {func_name}")
else:
    print("   FAIL: no stopped event after F11!")

# 8. Do a few more F11 steps inside WorkFunction
for i in range(5):
    print(f"\n{i+8}. === F11 #{i+2} ===")
    send("stepIn", {"threadId": tid})
    recv_until(lambda m: m.get("command") == "stepIn")
    sn, _ = recv_until(lambda m: m.get("type") == "event" and m.get("event") == "stopped", timeout=10)
    if sn:
        send("stackTrace", {"threadId": sn["body"].get("threadId", tid), "startFrame": 0, "levels": 1})
        stn, _ = recv_until(lambda m: m.get("command") == "stackTrace")
        if stn and stn["body"]["stackFrames"]:
            fn = stn["body"]["stackFrames"][0]
            print(f"   RIP={fn.get('instructionPointerReference','?')} line={fn.get('line','?')} func={fn.get('name','?')} reason={sn['body'].get('reason','?')}")
    else:
        print(f"   FAIL: no stopped after stepIn #{i+2}")
        break

# Cleanup
print("\nCleaning up...")
send("disconnect", {"terminateDebuggee": True})
time.sleep(1)
proc.kill()
print("\n=== StepIn Test Complete ===")
