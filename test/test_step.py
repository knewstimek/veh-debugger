"""DAP Step Test - F10(next) 동작 확인 (Launch mode)"""
import subprocess, json, sys, time, os

ADAPTER = os.path.join(os.path.dirname(__file__), "..", "build", "bin", "Release", "veh-debug-adapter.exe")
TARGET = os.path.join(os.path.dirname(__file__), "..", "build", "bin", "Release", "test_target.exe")
SOURCE = os.path.join(os.path.dirname(__file__), "..", "test_target", "main.cpp")
LOG = os.path.join(os.path.dirname(__file__), "step-test-adapter.log")

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

def show_log():
    try:
        with open(LOG, "r") as f:
            lines = f.readlines()
            print(f"\n=== Adapter Log (last 50 lines) ===")
            for line in lines[-50:]:
                print(f"   {line.rstrip()}")
    except Exception as ex:
        print(f"Could not read log: {ex}")

print("=== DAP Step Test (Launch mode) ===")

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
    show_log()
    proc.kill()
    sys.exit(1)
print(f"2. launch: success=True")

# 3. Set breakpoint at line 14 (printf in WorkFunction)
send("setBreakpoints", {
    "source": {"path": SOURCE},
    "breakpoints": [{"line": 14}]
})
bp_resp, _ = recv_until(lambda m: m.get("command") == "setBreakpoints")
if bp_resp:
    bps = bp_resp.get("body", {}).get("breakpoints", [])
    for bp in bps:
        print(f"3. BP line 14: verified={bp.get('verified')} id={bp.get('id')}")
else:
    print("3. BP: no response")

# 4. ConfigurationDone
send("configurationDone")
cfg_resp, msgs = recv_until(lambda m: m.get("command") == "configurationDone")
print(f"4. configurationDone")

# Wait for stopped (entry)
stopped, _ = recv_until(lambda m: m.get("type") == "event" and m.get("event") == "stopped", timeout=5)
if stopped:
    print(f"   stopped: reason={stopped['body'].get('reason')} tid={stopped['body'].get('threadId')}")

# 5. Continue → BP hit
send("continue", {"threadId": 1})
recv_until(lambda m: m.get("command") == "continue")

bp_hit, msgs = recv_until(
    lambda m: m.get("type") == "event" and m.get("event") == "stopped"
        and m.get("body",{}).get("reason") == "breakpoint", timeout=10)
if not bp_hit:
    print("FAIL: no breakpoint hit")
    for m in msgs:
        print(f"   {json.dumps(m)[:200]}")
    show_log()
    proc.kill()
    sys.exit(1)

tid = bp_hit["body"]["threadId"]
print(f"5. BP hit! threadId={tid}")

# 6. StackTrace before step
send("stackTrace", {"threadId": tid, "startFrame": 0, "levels": 3})
st, _ = recv_until(lambda m: m.get("command") == "stackTrace")
frames_before = st["body"]["stackFrames"] if st else []
if frames_before:
    f = frames_before[0]
    rip_before = f.get("instructionPointerReference", "?")
    line_before = f.get("line", "?")
    print(f"6. Before step: RIP={rip_before} line={line_before} func={f.get('name','?')}")

# 7. F10 - Next (step over)
print(f"\n7. === F10 (next) threadId={tid} ===")
send("next", {"threadId": tid})
next_resp, _ = recv_until(lambda m: m.get("command") == "next")
print(f"   next response: success={next_resp['success'] if next_resp else 'N/A'}")

step_stopped, msgs = recv_until(
    lambda m: m.get("type") == "event" and m.get("event") == "stopped", timeout=10)
if step_stopped:
    reason = step_stopped["body"].get("reason")
    step_tid = step_stopped["body"].get("threadId")
    print(f"   stopped: reason={reason} threadId={step_tid}")

    # Get new position
    send("stackTrace", {"threadId": step_tid, "startFrame": 0, "levels": 3})
    st2, _ = recv_until(lambda m: m.get("command") == "stackTrace")
    if st2 and st2["body"]["stackFrames"]:
        f2 = st2["body"]["stackFrames"][0]
        rip_after = f2.get("instructionPointerReference", "?")
        line_after = f2.get("line", "?")
        print(f"   After step:  RIP={rip_after} line={line_after}")
        if rip_before != rip_after:
            print(f"   >>> RIP CHANGED: {rip_before} -> {rip_after}")
        else:
            print(f"   >>> RIP DID NOT CHANGE!")
else:
    print("   FAIL: no stopped event after F10!")
    for m in msgs:
        print(f"   recv: {json.dumps(m)[:200]}")

# 8. Multiple consecutive source-line steps
prev_line = line_before
for i in range(2, 12):
    print(f"\n{i+6}. === F10 #{i} ===")
    send("next", {"threadId": tid})
    recv_until(lambda m: m.get("command") == "next")
    step_n, _ = recv_until(lambda m: m.get("type") == "event" and m.get("event") == "stopped", timeout=15)
    if step_n:
        reason = step_n["body"].get("reason", "?")
        step_tid = step_n["body"].get("threadId", tid)
        send("stackTrace", {"threadId": step_tid, "startFrame": 0, "levels": 1})
        st_n, _ = recv_until(lambda m: m.get("command") == "stackTrace")
        if st_n and st_n["body"]["stackFrames"]:
            fn = st_n["body"]["stackFrames"][0]
            cur_line = fn.get('line', '?')
            cur_func = fn.get('name', '?')
            print(f"   RIP={fn.get('instructionPointerReference','?')} line={cur_line} func={cur_func} reason={reason}")
            if cur_line != prev_line:
                print(f"   >>> LINE CHANGED: {prev_line} -> {cur_line}")
            prev_line = cur_line
        else:
            print(f"   stopped reason={reason} but no stack")
    else:
        print(f"   FAIL: no stopped after step #{i}")
        break

# Cleanup
print("\nCleaning up...")
send("disconnect", {"terminateDebuggee": True})
time.sleep(1)
proc.kill()
time.sleep(0.5)
show_log()
print("\n=== Test Complete ===")
