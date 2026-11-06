"""Native VEH thread coverage and breakpoint rearm boundaries."""
import ctypes
from ctypes import wintypes
import struct

from owned_mcp_client import OwnedMcpClient
from test_page_breakpoints import setup, program, tool, KERNEL

KERNEL.ReadProcessMemory.argtypes = (wintypes.HANDLE, ctypes.c_void_p,
    ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t))


def byte_at(pid, address):
    handle = KERNEL.OpenProcess(0x10, False, pid)
    assert handle
    try:
        value, count = ctypes.c_ubyte(), ctypes.c_size_t()
        assert KERNEL.ReadProcessMemory(handle, ctypes.c_void_p(address),
            ctypes.byref(value), 1, ctypes.byref(count)) and count.value == 1
        return value.value
    finally:
        KERNEL.CloseHandle(handle)


def start_worker(c, bits, entry):
    helper = tool(c, "veh_set_function_breakpoint", {"name":"PageWatchStart"})
    address = int(helper["address"], 0)
    tool(c, "veh_remove_breakpoint", {"id":helper["id"]})
    if bits == 64:
        raw = b"\x48\x83\xec\x28\x48\xb9"+struct.pack("<Q",entry)
        raw += b"\x48\xb8"+struct.pack("<Q",address)+b"\xff\xd0\x48\x83\xc4\x28\xc3"
    else:
        raw = b"\x68"+struct.pack("<I",entry)+b"\xb8"+struct.pack("<I",address)
        raw += b"\xff\xd0\x83\xc4\x04\xc3"
    result = tool(c, "veh_execute_shellcode", {"shellcode":raw.hex(),"timeout_ms":3000})
    assert result["exitCode"], result
    return result["exitCode"]


def check_new_thread_hardware():
    with OwnedMcpClient() as c:
        c.initialize("hardware-new-thread")
        pid, main, bits, data, code = setup(c)
        terminal = program(c, main, bits, data, code, [(0, 41)])
        bp = tool(c, "veh_set_data_breakpoint", {"address":hex(data)})
        worker = start_worker(c, bits, code)
        stop = tool(c, "veh_continue", {"threadId":worker,"wait":True,"timeout":4})
        assert stop.get("breakpointId") == bp["id"], ("first worker write missed hardware watch",stop)
        assert stop.get("breakpointType") == "hardware", stop
        tool(c, "veh_remove_data_breakpoint", {"id":bp["id"]})
    print("PASS a newly created thread's first data write hits the existing hardware watch")


def check_parked_software():
    with OwnedMcpClient() as c:
        c.initialize("software-parked")
        pid, main, bits, data, code = setup(c)
        terminal = program(c, main, bits, data, code, [(0, 42)])
        address = code + (10 if bits == 64 else 5)
        bp = tool(c, "veh_set_breakpoint", {"address":hex(address)})
        worker = start_worker(c, bits, code)
        stop = tool(c, "veh_continue", {"threadId":worker,"wait":True,"timeout":4})
        assert stop["breakpointId"] == bp["id"], stop
        assert byte_at(pid,address) == 0xCC, "parked software breakpoint was removed from shared code"
        other = tool(c, "veh_continue", {"threadId":main,"wait":True,"timeout":4})
        assert other.get("breakpointId") == bp["id"], ("peer passed a parked software breakpoint",other)
        assert byte_at(pid,address) == 0xCC
        tool(c, "veh_threads", {"action":"freeze","threadId":worker})
        end = tool(c, "veh_continue", {"threadId":main,"wait":True,"timeout":4})
        assert end["breakpointId"] == terminal["id"], end
        assert byte_at(pid,address) == 0xCC
        rows = tool(c, "veh_threads")["threads"]
        assert next(row for row in rows if row["id"]==worker)["frozen"], rows
        tool(c, "veh_threads", {"action":"thaw","threadId":worker})
        end = tool(c, "veh_continue", {"threadId":worker,"wait":True,"timeout":4})
        assert end["breakpointId"] == terminal["id"], end
    print("PASS INT3 stays installed while two threads are parked at the same breakpoint")


def check_thread_entry_before_loader_tls():
    nt = ctypes.WinDLL("ntdll")
    nt.NtCreateThreadEx.argtypes = (ctypes.POINTER(wintypes.HANDLE),wintypes.DWORD,
        ctypes.c_void_p,wintypes.HANDLE,ctypes.c_void_p,ctypes.c_void_p,wintypes.DWORD,
        ctypes.c_size_t,ctypes.c_size_t,ctypes.c_size_t,ctypes.c_void_p)
    nt.NtCreateThreadEx.restype = ctypes.c_long
    KERNEL.GetExitCodeThread.argtypes = (wintypes.HANDLE,ctypes.POINTER(wintypes.DWORD))
    with OwnedMcpClient() as c:
        c.initialize("thread-before-loader-tls")
        pid, main, bits, data, code = setup(c)
        tool(c, "veh_write_memory", {"address":hex(code),"data":"31c0c3" if bits==64 else "31c0c20400"})
        process = KERNEL.OpenProcess(0x2|0x400|0x100000,False,pid)
        assert process
        thread = wintypes.HANDLE()
        try:
            status = nt.NtCreateThreadEx(ctypes.byref(thread),0x1FFFFF,None,process,
                ctypes.c_void_p(code),None,0x22,0,0,0,None)  # skip loader init/thread attach
            assert status>=0, hex(status&0xFFFFFFFF)
            assert KERNEL.WaitForSingleObject(thread,5000)==0, "early native thread stalled"
            result = wintypes.DWORD()
            assert KERNEL.GetExitCodeThread(thread,ctypes.byref(result)) and result.value==0, hex(result.value)
            assert KERNEL.WaitForSingleObject(process,0)==258, "entry guard crashed the process before CRT TLS"
        finally:
            if thread:KERNEL.CloseHandle(thread)
            KERNEL.CloseHandle(process)
    print("PASS private thread-entry guard runs without CRT loader TLS")


def check_software_and_hardware():
    with OwnedMcpClient() as c:
        c.initialize("software-hardware-same-instruction")
        pid, main, bits, data, code = setup(c)
        terminal = program(c, main, bits, data, code, [(0, 44)])
        software = tool(c, "veh_set_breakpoint", {"address":hex(code+(10 if bits==64 else 5))})
        hardware = tool(c, "veh_set_data_breakpoint", {"address":hex(data)})
        worker = start_worker(c, bits, code)
        first = tool(c, "veh_continue", {"threadId":worker,"wait":True,"timeout":4})
        assert first["breakpointId"] == software["id"], first
        second = tool(c, "veh_continue", {"threadId":worker,"wait":True,"timeout":4})
        assert second["breakpointId"] == hardware["id"], ("software rearm swallowed the data trap",second)
    print("PASS software instruction retry preserves a simultaneous hardware data trap")


def check_hardware_detach():
    with OwnedMcpClient() as c:
        c.initialize("hardware-detach")
        pid, main, bits, data, code = setup(c)
        terminal = program(c, main, bits, data, code, [(0, 45)])
        tool(c, "veh_remove_breakpoint", {"id":terminal["id"]})
        end = int(terminal["address"],0)
        write = code+(10 if bits==64 else 5)
        jump = b"\xe9"+struct.pack("<i",write-(end+5))
        tool(c, "veh_write_memory", {"address":hex(end),"data":jump.hex()})
        watch = tool(c, "veh_set_data_breakpoint", {"address":hex(data)})
        worker = start_worker(c, bits, code)
        stop = tool(c, "veh_continue", {"threadId":worker,"wait":True,"timeout":4})
        assert stop["breakpointId"] == watch["id"], stop
        process = KERNEL.OpenProcess(0x100000,False,pid)
        assert process
        try:
            tool(c, "veh_detach")
            assert KERNEL.WaitForSingleObject(process,200)==258, "hardware DR was left armed after detach"
        finally:KERNEL.CloseHandle(process)
    print("PASS detach disarms a parked worker before it keeps writing")


def check_hardware_apply_failure():
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    KERNEL.OpenThread.argtypes = (wintypes.DWORD,wintypes.BOOL,wintypes.DWORD)
    KERNEL.OpenThread.restype = wintypes.HANDLE
    adv.GetKernelObjectSecurity.argtypes = (wintypes.HANDLE,wintypes.DWORD,ctypes.c_void_p,wintypes.DWORD,ctypes.POINTER(wintypes.DWORD))
    adv.SetKernelObjectSecurity.argtypes = (wintypes.HANDLE,wintypes.DWORD,ctypes.c_void_p)
    adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = (
        wintypes.LPCWSTR,wintypes.DWORD,ctypes.POINTER(ctypes.c_void_p),ctypes.POINTER(wintypes.DWORD))
    KERNEL.LocalFree.argtypes = (ctypes.c_void_p,)
    with OwnedMcpClient() as c:
        c.initialize("hardware-apply-failure")
        pid, main, bits, data, code = setup(c)
        terminal = program(c, main, bits, data, code, [(0, 43)])
        tool(c, "veh_remove_breakpoint", {"id":terminal["id"]})
        prior = tool(c, "veh_set_data_breakpoint", {"address":hex(data+8)})
        worker = start_worker(c, bits, code)  # runs in an owned code loop
        handle = KERNEL.OpenThread(0x40000|0x20000|0x800,False,worker)
        assert handle
        needed = wintypes.DWORD()
        adv.GetKernelObjectSecurity(handle,4,None,0,ctypes.byref(needed))
        old = ctypes.create_string_buffer(needed.value)
        assert adv.GetKernelObjectSecurity(handle,4,old,len(old),ctypes.byref(needed))
        denied = ctypes.c_void_p()
        assert adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            "D:(D;;0x10;;;WD)(A;;GA;;;WD)",1,ctypes.byref(denied),None)
        try:
            assert adv.SetKernelObjectSecurity(handle,4,denied)
            added = c.tool("veh_set_data_breakpoint", {"address":hex(data+16)})
            assert "error" in added, ("partially applied DR watch was reported successful",added)
            removed = c.tool("veh_remove_data_breakpoint", {"id":prior["id"]})
            assert "error" in removed, ("partially removed DR watch was reported successful",removed)
            rows = tool(c, "veh_list_breakpoints")["hardware"]
            assert [row["id"] for row in rows] == [prior["id"]], rows
        finally:
            assert adv.SetKernelObjectSecurity(handle,4,old)
            KERNEL.LocalFree(denied)
            KERNEL.CloseHandle(handle)
        tool(c, "veh_remove_data_breakpoint", {"id":prior["id"]})
    print("PASS real thread access denial fails DR creation/removal and retains prior tracking")


if __name__ == "__main__":
    check_new_thread_hardware()
    check_parked_software()
    check_software_and_hardware()
    check_hardware_apply_failure()
    check_thread_entry_before_loader_tls()
    check_hardware_detach()
