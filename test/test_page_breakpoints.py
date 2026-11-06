"""Real VEH page watches: sharing, fault filtering, rearm, steps and cleanup."""
import ctypes
from ctypes import wintypes
import json
from pathlib import Path
import struct
import tempfile
import subprocess
import time

from build_paths import RELEASE
from owned_mcp_client import OwnedMcpClient
from test_trace_basic_blocks import MemoryBasicInformation

TARGET = str(Path(RELEASE) / "test_target.exe")
AGENT = str(Path(RELEASE) / "guest_backend_fixture.exe")
KERNEL = ctypes.WinDLL("kernel32", use_last_error=True)
KERNEL.OpenProcess.restype = wintypes.HANDLE
KERNEL.CloseHandle.argtypes = (wintypes.HANDLE,)
KERNEL.VirtualQueryEx.argtypes = (wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t)
KERNEL.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)


def protect(pid, address):
    h = KERNEL.OpenProcess(0x1000 | 0x0400, False, pid)
    assert h, ctypes.get_last_error()
    try:
        info = MemoryBasicInformation()
        assert KERNEL.VirtualQueryEx(h, ctypes.c_void_p(address), ctypes.byref(info), ctypes.sizeof(info))
        return info.Protect
    finally:
        KERNEL.CloseHandle(h)


def tool(c, name, args=None):
    result = c.tool(name, args or {})
    assert "error" not in result, (name, result)
    return result


def setup(c, pid=None):
    launched = tool(c, "veh_launch", {"program": TARGET, "stopOnEntry": True}) if pid is None else tool(c, "veh_attach", {"pid":pid})
    bp = tool(c, "veh_set_function_breakpoint", {"name": "TraceCoverageTarget"})
    stop = tool(c, "veh_continue", {"wait": True, "timeout": 10})
    tid = stop["threadId"]
    tool(c, "veh_remove_breakpoint", {"id": bp["id"]})
    regs = tool(c, "veh_registers", {"threadId": tid})["registers"]
    bits = 32 if "eip" in regs else 64
    data = int(tool(c, "veh_allocate_memory", {"size": 8192, "protection": "rw"})["address"], 0)
    code = int(tool(c, "veh_allocate_memory", {"size": 4096, "protection": "rwx"})["address"], 0)
    return launched["pid"], tid, bits, data, code


def program(c, tid, bits, data, code, accesses):
    raw = (b"\x48\xb8" + struct.pack("<Q", data)) if bits == 64 else b"\xb8" + struct.pack("<I", data)
    for offset, value in accesses:
        if value is None:
            raw += bytes([0x8b, 0x48, offset])  # mov ecx,[a+offset]
        else:
            raw += bytes([0xc7, 0x40, offset]) + struct.pack("<I", value)
    terminal = code + len(raw)
    raw += b"\x90\xeb\xfe"  # terminal software BP; safe infinite loop after detach
    tool(c, "veh_write_memory", {"address": hex(code), "data": raw.hex()})
    tool(c, "veh_set_register", {"threadId": tid, "name": "eip" if bits == 32 else "rip", "value": hex(code)})
    bp = tool(c, "veh_set_breakpoint", {"address": hex(terminal)})
    return bp


def watch(c, address, **extra):
    return tool(c, "veh_set_data_breakpoint", dict(address=hex(address), method="page", size=4, **extra))


def hit(c, bp, address, access="write"):
    stop = tool(c, "veh_continue", {"wait": True, "timeout": 4})
    assert stop["breakpointId"] == bp["id"] and stop["breakpointType"] == "page", stop
    assert int(stop["accessedAddress"], 0) == address and stop["access"] == access, stop
    assert stop["coverage"] == "best_effort" and stop["registersAt"] == "before_instruction", stop
    assert not stop["rearmFailed"] and stop["registers"], stop
    ip = "eip" if "eip" in stop["registers"] else "rip"
    assert int(stop["registers"][ip],0) == int(stop["address"],0), stop
    return stop


def run():
    with OwnedMcpClient() as c:
        c.initialize("page-breakpoints")
        pid, tid, bits, data, code = setup(c)
        # Four DR slots remain available even with more than four page watches.
        extra = [watch(c, data + 64 + 8*i) for i in range(5)]
        hw = [tool(c, "veh_set_data_breakpoint", {"address": hex(data + 128 + i*4)}) for i in range(4)]
        assert all("slot" not in row and row["method"] == "page" for row in extra)
        for row in hw + extra:
            tool(c, "veh_remove_data_breakpoint", {"id": row["id"]})
        assert protect(pid, data) == 4

        terminal = program(c, tid, bits, data, code, [(8, 9), (0, 1), (0, 2)])
        bp = watch(c, data)
        assert protect(pid, data) & 0x100
        hit(c, bp, data)  # neighbor write did not become a user stop
        assert protect(pid, data) & 0x100, "guard must remain armed while parked"
        observed = bytes.fromhex(tool(c, "veh_read_memory", {"address":hex(data),"size":12})["hex"])
        assert struct.unpack_from("<I", observed, 0)[0] == 0 and struct.unpack_from("<I", observed, 8)[0] == 9
        step = tool(c, "veh_step_in", {"threadId": tid})
        assert step["stepCompleted"], step
        assert protect(pid, data) & 0x100
        hit(c, bp, data)
        end = tool(c, "veh_continue", {"wait": True, "timeout": 4})
        assert end["breakpointId"] == terminal["id"], end
        tool(c, "veh_remove_data_breakpoint", {"id": bp["id"]})
        assert protect(pid, data) == 4
        tool(c, "veh_remove_breakpoint", {"id": terminal["id"]})

        # Simultaneous hardware data traps remain visible after the page rearm.
        terminal = program(c, tid, bits, data, code, [(0, 9)])
        bp = watch(c, data)
        hw = tool(c, "veh_set_data_breakpoint", {"address":hex(data)})
        hit(c, bp, data)
        after = tool(c, "veh_continue", {"wait":True,"timeout":4})
        assert after["breakpointId"] == hw["id"] and after["breakpointType"] == "hardware", after
        for row in (hw, bp):
            tool(c, "veh_remove_data_breakpoint", {"id":row["id"]})
        assert tool(c, "veh_continue", {"wait":True,"timeout":4})["breakpointId"] == terminal["id"]
        tool(c, "veh_remove_breakpoint", {"id":terminal["id"]})

        # INT3 rearm can own TF before the same instruction faults on a page.
        terminal = program(c, tid, bits, data, code, [(0, 12)])
        write_ip = code + (10 if bits == 64 else 5)
        sw = tool(c, "veh_set_breakpoint", {"address":hex(write_ip)})
        bp = watch(c, data)
        assert tool(c, "veh_continue", {"wait":True,"timeout":4})["breakpointId"] == sw["id"]
        hit(c, bp, data)
        final = tool(c, "veh_continue", {"wait":True,"timeout":4})
        assert final.get("breakpointId") == terminal["id"], final
        tool(c, "veh_remove_data_breakpoint", {"id":bp["id"]})
        for row in (sw, terminal):
            tool(c, "veh_remove_breakpoint", {"id":row["id"]})

        # Two non-overlapping ranges share a page; removing one preserves the other.
        terminal = program(c, tid, bits, data, code, [(0, 3), (8, 4), (8, 5)])
        batch = tool(c, "veh_batch", {"steps": [
            {"tool": "veh_set_data_breakpoint", "args": {"address": hex(data + offset), "method": "page"}}
            for offset in (0, 8)]})
        assert batch["failed"] == 0, batch
        first, second = [row["result"] for row in batch["results"]]
        hit(c, first, data)
        tool(c, "veh_remove_data_breakpoint", {"id": first["id"]})
        hit(c, second, data+8)
        hit(c, second, data+8)  # same remaining watch rearms
        tool(c, "veh_remove_data_breakpoint", {"id": second["id"]})
        assert protect(pid, data) == 4
        assert tool(c, "veh_continue", {"wait":True,"timeout":4})["breakpointId"] == terminal["id"]
        tool(c, "veh_remove_breakpoint", {"id": terminal["id"]})

        # Recreating a removed watch at a parked guard stop must arm immediately.
        terminal = program(c, tid, bits, data, code, [(0, 31), (0, 32)])
        previous = watch(c, data)
        hit(c, previous, data)
        tool(c, "veh_remove_data_breakpoint", {"id":previous["id"]})
        assert protect(pid, data) == 4
        recreated = watch(c, data)
        assert recreated["id"] != previous["id"]
        assert protect(pid, data) & 0x100, "recreated parked watch was not armed"
        hit(c, recreated, data)  # first write retried; second access is a new hit
        tool(c, "veh_remove_data_breakpoint", {"id":recreated["id"]})
        assert tool(c, "veh_continue", {"wait":True,"timeout":4})["breakpointId"] == terminal["id"]
        tool(c, "veh_remove_breakpoint", {"id":terminal["id"]})

        # Original read-only protection survives removal after a read watch.
        tool(c, "veh_protect_memory", {"address":hex(data),"size":4096,"protection":"r"})
        terminal = program(c, tid, bits, data, code, [(0, None)])
        ro = watch(c, data, type="readwrite")
        hit(c, ro, data, "read")
        tool(c, "veh_remove_data_breakpoint", {"id":ro["id"]})
        assert tool(c, "veh_continue", {"wait":True,"timeout":4})["breakpointId"] == terminal["id"]
        assert protect(pid, data) == 2
        tool(c, "veh_remove_breakpoint", {"id":terminal["id"]})
        tool(c, "veh_protect_memory", {"address":hex(data),"size":4096,"protection":"rw"})
        for args in ({"address":hex(data+4094),"method":"page","size":4},
                     {"address":hex(code),"method":"page"},
                     {"address":hex(data),"method":"page","type":"execute"},
                     {"address":hex(data),"method":"page","condition":"value != 0"},
                     {"address":hex(data),"method":"page","condition":"[0x1000] == 1"}):
            assert "error" in c.tool("veh_set_data_breakpoint", args), args
        assert protect(pid, data) == 4
        # Cleanup must not overwrite a later protection change made elsewhere.
        terminal = program(c, tid, bits, data, code, [(0, 23)])
        bp = watch(c, data)
        hit(c, bp, data)
        handle = KERNEL.OpenProcess(0x0008, False, pid)
        assert handle
        KERNEL.VirtualProtectEx.argtypes = (wintypes.HANDLE,ctypes.c_void_p,ctypes.c_size_t,wintypes.DWORD,ctypes.POINTER(wintypes.DWORD))
        try:
            old = wintypes.DWORD()
            assert KERNEL.VirtualProtectEx(handle,ctypes.c_void_p(data),4096,2,ctypes.byref(old))
        finally:
            KERNEL.CloseHandle(handle)
        tool(c, "veh_remove_data_breakpoint", {"id":bp["id"]})
        assert protect(pid,data)==2
        tool(c, "veh_set_register", {"threadId":tid,"name":"eip" if bits==32 else "rip","value":terminal["address"]})
        assert tool(c, "veh_continue", {"wait":True,"timeout":4})["breakpointId"] == terminal["id"]
        tool(c, "veh_remove_breakpoint", {"id":terminal["id"]})
        tool(c, "veh_protect_memory", {"address":hex(data),"size":4096,"protection":"rw"})
        terminal = program(c, tid, bits, data, code, [(0, None), (8, 8)])
        bp = watch(c, data, type="readwrite")
        hit(c, bp, data, "read")
        # Detach at a guard stop must restore protection and borrowed TF.
        assert tool(c, "veh_detach")["success"]
        assert protect(pid, data) == 4
        h = KERNEL.OpenProcess(0x100000, False, pid)
        assert h
        try:
            assert KERNEL.WaitForSingleObject(h, 150) == 258, "target died after guard-stop detach"
        finally:
            KERNEL.CloseHandle(h)

    # Own actions use the same page method; hit actions auto-continue to a real terminal BP.
    with tempfile.TemporaryDirectory(prefix="veh-page-actions-") as d:
        log = Path(d)/"mcp.log"
        with OwnedMcpClient(args=["--log="+str(log)]) as c:
            c.initialize("page-actions")
            pid, tid, bits, data, code = setup(c)
            terminal = program(c, tid, bits, data, code, [(0, 7)])
            bp = watch(c, data, action=[{"tool":"veh_set_data_breakpoint",
                "args":{"address":hex(data+8),"method":"page"}}])
            end = tool(c, "veh_continue", {"wait":True,"timeout":4})
            assert end["breakpointId"] == terminal["id"], end
            rows = tool(c, "veh_list_breakpoints")["page"]
            assert len(rows) == 2 and any(int(row["address"],0) == data+8 for row in rows), rows
            c.wait_notification("notifications/logging", lambda p:"action executing" in str(p.get("data","")), timeout=3)
            for row in rows:
                tool(c, "veh_remove_data_breakpoint", {"id":row["id"]})
    with OwnedMcpClient() as c:
        c.initialize("page-unsupported")
        tool(c, "veh_attach", {"pid":4242,"target_scope":"guest","agent":AGENT,
                              "agent_args":["--metadata","control-ok"]})
        args = {"address":"0x1000","method":"page"}
        result = c.tool("veh_set_data_breakpoint", args)
        assert "does not advertise" in result.get("error",""), result
        batch = tool(c, "veh_batch", {"steps":[{"tool":"veh_set_data_breakpoint","args":args}]})
        assert batch["failed"] == 1 and batch["results"][0]["result"] == result, batch
    print("PASS native page watches, DR independence, address/read/write filters, step/rearm, shared-page removal, detach and nested parity")



def check_two_threads():
    with OwnedMcpClient() as c:
        c.initialize("page-threads")
        pid, main_tid, bits, data, main_code = setup(c)
        worker_code = int(tool(c, "veh_allocate_memory", {"size":4096,"protection":"rwx"})["address"],0)
        main_end = program(c, main_tid, bits, data, main_code, [(0, 21)])
        worker_end = program(c, main_tid, bits, data, worker_code, [(8, 22)])
        tool(c, "veh_set_register", {"threadId":main_tid, "name":"eip" if bits==32 else "rip", "value":hex(main_code)})
        helper = tool(c, "veh_set_function_breakpoint", {"name":"PageWatchStart"})
        helper_addr = int(helper["address"],0)
        tool(c, "veh_remove_breakpoint", {"id":helper["id"]})
        entry = tool(c, "veh_set_breakpoint", {"address":hex(worker_code)})
        if bits == 64:
            start = b"\x48\x83\xec\x28\x48\xb9"+struct.pack("<Q",worker_code)+b"\x48\xb8"+struct.pack("<Q",helper_addr)+b"\xff\xd0\x48\x83\xc4\x28\xc3"
        else:
            start = b"\x68"+struct.pack("<I",worker_code)+b"\xb8"+struct.pack("<I",helper_addr)+b"\xff\xd0\x83\xc4\x04\xc3"
        worker = tool(c, "veh_execute_shellcode", {"shellcode":start.hex(),"timeout_ms":3000})
        worker_tid = worker["exitCode"]
        assert worker_tid and worker_tid != main_tid, worker
        tool(c, "veh_registers", {"threadId":worker_tid})
        initial = tool(c, "veh_continue", {"threadId":worker_tid,"wait":True,"timeout":4})
        assert initial["breakpointId"] == entry["id"], initial  #acknowledge unreported entry stop
        first, second = watch(c, data), watch(c, data+8)
        a = tool(c, "veh_continue", {"threadId":worker_tid,"wait":True,"timeout":4})
        assert a["breakpointId"] == second["id"], a
        assert protect(pid,data)&0x100
        b = tool(c, "veh_continue", {"threadId":main_tid,"wait":True,"timeout":4})
        assert b["breakpointId"] == first["id"], b
        assert protect(pid,data)&0x100
        # Independent leases: resuming one cannot lose the other's parked guard.
        assert tool(c, "veh_continue", {"threadId":main_tid,"wait":True,"timeout":4})["breakpointId"] == main_end["id"]
        tool(c, "veh_remove_data_breakpoint", {"id":first["id"]})
        assert protect(pid,data)&0x100
        assert tool(c, "veh_continue", {"threadId":worker_tid,"wait":True,"timeout":4})["breakpointId"] == worker_end["id"]
        tool(c, "veh_remove_data_breakpoint", {"id":second["id"]})
        assert protect(pid,data)==4
    print("PASS two live threads sharing one guarded page with independent parked/rearm leases")


def check_original_fault():
    with OwnedMcpClient() as c:
        c.initialize("page-original-fault")
        pid, tid, bits, data, code = setup(c)
        terminal = program(c, tid, bits, data, code, [(0, 13)])
        tool(c, "veh_protect_memory", {"address":hex(data),"size":4096,"protection":"r"})
        bp = watch(c, data)
        fault = tool(c, "veh_continue", {"wait":True,"timeout":4})
        # Windows can report the underlying write AV before a guard alarm.
        if fault.get("breakpointType") == "page":
            assert fault["breakpointId"] == bp["id"], fault
            fault = tool(c, "veh_continue", {"wait":True,"timeout":4})
        assert fault["reason"] == "exception", fault
        info = tool(c, "veh_exception_info", {"threadId":tid})
        assert "C0000005" in json.dumps(info).upper(), info
        tool(c, "veh_remove_data_breakpoint", {"id":bp["id"]})
        assert protect(pid,data)==2
        tool(c, "veh_terminate")  #do not resume an actual unhandled target AV
    print("PASS original access violation preserved and page protection restored")


def check_disconnect():
    # Target is outside the MCP's private job so we can observe broken-pipe
    # cleanup, then explicitly terminate and wait for this exact owned process.
    target = subprocess.Popen([TARGET], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0))
    try:
        with OwnedMcpClient() as c:
            c.initialize("page-disconnect")
            pid, tid, bits, data, code = setup(c, target.pid)
            terminal = program(c, tid, bits, data, code, [(0, 24)])
            bp = watch(c, data)
            hit(c, bp, data)
            c.proc.kill()
            c.proc.wait(timeout=5)
            deadline = time.monotonic()+5
            while protect(pid,data)&0x100:
                assert time.monotonic()<deadline, "broken pipe did not restore original protection"
                time.sleep(0.02)
            assert protect(pid,data)==4
            assert KERNEL.WaitForSingleObject(wintypes.HANDLE(int(target._handle)),150)==258, "target died after broken-pipe cleanup"
    finally:
        if target.poll() is None:
            target.terminate()
            try:target.wait(timeout=5)
            except subprocess.TimeoutExpired:
                target.kill()
                target.wait(timeout=5)
    print("PASS broken-pipe cleanup restores guarded data and borrowed TF without killing the target")

if __name__ == "__main__":
    run()
    check_two_threads()
    check_original_fault()
    check_disconnect()
