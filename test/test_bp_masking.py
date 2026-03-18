"""BP masking test - ReadMemory should return original bytes, not INT3 (0xCC)"""
import subprocess, json, sys, time, base64

ADAPTER = r"D:\News\Hack\Engine\VEHDebugger\for VSCode Extension\build\bin\Release\veh-debug-adapter.exe"
TARGET = r"D:\News\Hack\Engine\VEHDebugger\for VSCode Extension\build\bin\Release\test_target.exe"
SOURCE = r"D:\News\Hack\Engine\VEHDebugger\for VSCode Extension\test_target\main.cpp"

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

print("=== BP Masking Test ===")

# 1. Initialize
send("initialize", {"adapterID": "veh", "clientID": "test"})
recv_until(lambda m: m.get("command") == "initialize" and m.get("type") == "response")
print("1. initialized")

# 2. Launch
send("launch", {"program": TARGET, "stopOnEntry": True})
launch_resp = None
for _ in range(15):
    msg = recv(timeout=3)
    if msg is None: continue
    if msg.get("type") == "response" and msg.get("command") == "launch":
        launch_resp = msg
        break
if not launch_resp or not launch_resp.get("success"):
    print(f"FAIL: launch failed")
    proc.kill()
    sys.exit(1)
print("2. launched")

# 3. Set BP at line 14 (printf in WorkFunction)
send("setBreakpoints", {
    "source": {"path": SOURCE},
    "breakpoints": [{"line": 14}]
})
bp_resp, _ = recv_until(lambda m: m.get("command") == "setBreakpoints")
bp_addr = None
if bp_resp and bp_resp.get("body", {}).get("breakpoints"):
    bp = bp_resp["body"]["breakpoints"][0]
    ref = bp.get("instructionReference", "")
    if ref:
        bp_addr = int(ref, 16)
    print(f"3. BP set: verified={bp.get('verified')} addr={ref}")
else:
    print("3. BP set but no address info")

# 4. ConfigurationDone + wait for entry stop
send("configurationDone")
recv_until(lambda m: m.get("command") == "configurationDone")
stopped, _ = recv_until(lambda m: m.get("type") == "event" and m.get("event") == "stopped", timeout=5)
print(f"4. stopped at entry")

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
print(f"5. BP hit! threadId={tid}")

# 6. Get actual BP address from stack trace
send("stackTrace", {"threadId": tid, "startFrame": 0, "levels": 1})
st, _ = recv_until(lambda m: m.get("command") == "stackTrace")
if st and st["body"]["stackFrames"]:
    ref = st["body"]["stackFrames"][0].get("instructionPointerReference", "")
    if ref:
        bp_addr = int(ref, 16)
print(f"6. BP address: 0x{bp_addr:X}" if bp_addr else "6. No BP address")

if not bp_addr:
    print("FAIL: could not determine BP address")
    send("disconnect", {"terminateDebuggee": True})
    time.sleep(0.5)
    proc.kill()
    sys.exit(1)

# 7. ReadMemory at BP address - should NOT contain 0xCC at offset 0
send("readMemory", {
    "memoryReference": f"0x{bp_addr:X}",
    "count": 16
})
mem_resp, _ = recv_until(lambda m: m.get("command") == "readMemory")

if mem_resp and mem_resp.get("success"):
    data_b64 = mem_resp["body"].get("data", "")
    data = base64.b64decode(data_b64)
    first_byte = data[0] if data else None
    hex_str = " ".join(f"{b:02X}" for b in data[:16])
    print(f"7. ReadMemory at 0x{bp_addr:X}: {hex_str}")

    if first_byte == 0xCC:
        print("   >>> FAIL: First byte is 0xCC (INT3) - BP masking NOT working!")
    else:
        print(f"   >>> OK: First byte is 0x{first_byte:02X} (original instruction, not INT3)")
        print("   BP masking is working correctly!")
else:
    print(f"7. ReadMemory failed: {mem_resp}")

# 8. Also test disassemble at BP address
send("disassemble", {
    "memoryReference": f"0x{bp_addr:X}",
    "instructionCount": 3,
    "offset": 0
})
dis_resp, _ = recv_until(lambda m: m.get("command") == "disassemble")
if dis_resp and dis_resp.get("success"):
    insns = dis_resp["body"].get("instructions", [])
    print(f"8. Disassemble at BP address:")
    for insn in insns[:3]:
        addr = insn.get("address", "?")
        text = insn.get("instruction", "?")
        print(f"   {addr}: {text}")
    if insns and "int3" in insns[0].get("instruction", "").lower():
        print("   >>> FAIL: Disassembly shows INT3 at BP address!")
    else:
        print("   >>> OK: Disassembly shows original instruction")
else:
    print(f"8. Disassemble failed: {dis_resp}")

# Cleanup
print("\nCleaning up...")
send("disconnect", {"terminateDebuggee": True})
time.sleep(1)
proc.kill()
print("=== BP Masking Test Complete ===")
