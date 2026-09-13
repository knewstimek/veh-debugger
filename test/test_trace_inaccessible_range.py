"""Trace startup tolerates inaccessible gaps and internal SEH probes never self-stop."""
import ctypes
import os
import time

from mcp_test_client import McpClient


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BUILD_DIR = os.environ.get("VEH_TEST_BUILD_DIR", os.path.join(ROOT, "build"))
TARGET = os.path.join(BUILD_DIR, "bin", "Release", "test_target.exe")
PAGE_SIZE = 4096


def make_page_inaccessible(pid, address):
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.VirtualProtectEx.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
        ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32),
    ]
    kernel32.VirtualProtectEx.restype = ctypes.c_int
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int

    handle = kernel32.OpenProcess(0x0008, False, pid)  # PROCESS_VM_OPERATION
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        old_protection = ctypes.c_uint32()
        if not kernel32.VirtualProtectEx(handle, ctypes.c_void_p(address), PAGE_SIZE,
                                         0x01, ctypes.byref(old_protection)):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        kernel32.CloseHandle(handle)


def main():
    client = McpClient()
    try:
        client.initialize("trace-inaccessible-range-test")
        launch = client.tool("veh_launch", {"program": TARGET, "stopOnEntry": True})
        assert launch.get("success"), launch
        breakpoint = client.tool("veh_set_function_breakpoint", {"name": "TraceCoverageTarget"})
        assert breakpoint.get("success"), breakpoint
        stopped = client.tool("veh_continue", {"wait": True, "timeout": 10}, timeout=15)
        assert stopped.get("reason") == "breakpoint", stopped
        thread_id = stopped["threadId"]

        # MemoryManager::Read uses a local __try/__except probe on the IPC thread.
        # Its access violation must return to SEH instead of becoming a debugger stop
        # that only the now-blocked IPC thread could resume.
        started = time.monotonic()
        invalid_read = client.tool("veh_read_memory", {"address": "0x1", "size": 1}, timeout=5)
        assert invalid_read.get("error"), invalid_read
        assert time.monotonic() - started < 5, invalid_read

        allocation = client.tool("veh_allocate_memory", {
            "size": PAGE_SIZE * 3, "protection": "rwx",
        })
        assert allocation.get("success"), allocation
        code = int(allocation["address"], 0)
        assert client.tool("veh_write_memory", {
            "address": hex(code), "data": "eb fe",
        }).get("success")
        make_page_inaccessible(launch["pid"], code + PAGE_SIZE)

        registers = client.tool("veh_registers", {"threadId": thread_id})["registers"]
        ip_name = "rip" if "rip" in registers else "eip"
        assert client.tool("veh_set_register", {
            "threadId": thread_id, "name": ip_name, "value": hex(code),
        }).get("success")
        trace = client.tool("veh_trace_basic_blocks", {
            "threadId": thread_id,
            "start": hex(code),
            "end": hex(code + PAGE_SIZE * 3),
            "max_steps": 16,
            "timeout_ms": 5000,
            "stack_bytes": 0,
        }, timeout=15)
        assert trace.get("stop_reason") == "max_steps", trace
        assert trace.get("steps_executed") == 16, trace
        print({
            "invalid_read": invalid_read["error"],
            "stop_reason": trace["stop_reason"],
            "steps_executed": trace["steps_executed"],
        })
    finally:
        client.close()


if __name__ == "__main__":
    main()
