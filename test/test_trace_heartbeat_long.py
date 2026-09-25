"""Regression: a synchronous trace may legitimately outlive the heartbeat window."""
import ctypes
import os
import threading
import time

from mcp_test_client import McpClient


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BUILD_DIR = os.environ.get("VEH_TEST_BUILD_DIR", os.path.join(ROOT, "build"))
TARGET = os.path.join(BUILD_DIR, "bin", "Release", "test_target.exe")


def suspend_owned_target(pid, duration, errors):
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    ntdll = ctypes.WinDLL("ntdll")
    kernel32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int
    ntdll.NtSuspendProcess.argtypes = [ctypes.c_void_p]
    ntdll.NtSuspendProcess.restype = ctypes.c_long
    ntdll.NtResumeProcess.argtypes = [ctypes.c_void_p]
    ntdll.NtResumeProcess.restype = ctypes.c_long
    handle = kernel32.OpenProcess(0x0800, False, pid)  # PROCESS_SUSPEND_RESUME
    if not handle:
        errors.append(f"OpenProcess failed: {ctypes.get_last_error()}")
        return
    suspended = False
    try:
        time.sleep(0.1)
        status = ntdll.NtSuspendProcess(handle)
        if status != 0:
            errors.append(f"NtSuspendProcess failed: 0x{status & 0xFFFFFFFF:08X}")
            return
        suspended = True
        time.sleep(duration)
    finally:
        if suspended:
            status = ntdll.NtResumeProcess(handle)
            if status != 0:
                errors.append(f"NtResumeProcess failed: 0x{status & 0xFFFFFFFF:08X}")
        kernel32.CloseHandle(handle)


def main():
    client = McpClient()
    suspender = None
    suspend_errors = []
    try:
        client.initialize("trace-heartbeat-long-test")
        launch = client.tool("veh_launch", {"program": TARGET, "stopOnEntry": True})
        assert launch.get("success"), launch
        breakpoint = client.tool("veh_set_function_breakpoint", {"name": "TraceCoverageTarget"})
        assert breakpoint.get("success"), breakpoint
        stop = client.tool("veh_continue", {"wait": True, "timeout": 10}, timeout=15)
        assert stop.get("reason") == "breakpoint", stop
        thread_id = stop["threadId"]
        registers = client.tool("veh_registers", {"threadId": thread_id})["registers"]
        ip_name = "rip" if "rip" in registers else "eip"

        allocation = client.tool("veh_allocate_memory", {"size": 4096, "protection": "rwx"})
        assert allocation.get("success"), allocation
        loop = int(allocation["address"], 0)
        assert client.tool("veh_write_memory", {
            "address": hex(loop), "data": "eb fe",
        }).get("success")
        assert client.tool("veh_set_register", {
            "threadId": thread_id, "name": ip_name, "value": hex(loop),
        }).get("success")

        suspender = threading.Thread(
            target=suspend_owned_target, args=(launch["pid"], 32, suspend_errors), daemon=False)
        suspender.start()
        trace = client.tool("veh_trace_basic_blocks", {
            "threadId": thread_id, "start": hex(loop), "end": hex(loop + 2),
            "max_steps": 5_000_000, "timeout_ms": 36_000, "stack_bytes": 0,
        }, timeout=60)
        suspender.join(timeout=40)
        assert not suspender.is_alive(), "target suspender did not finish"
        assert not suspend_errors, suspend_errors
        # The trace ends on its own timeout, independent of single-step speed (x86 is slower).
        assert trace.get("stop_reason") == "timeout", trace
        assert trace.get("elapsed_ms", 0) >= 32_000, trace
        assert trace.get("steps_executed", 0) > 0, trace
        print({
            "stop_reason": trace["stop_reason"],
            "elapsed_ms": trace["elapsed_ms"],
            "steps_executed": trace["steps_executed"],
        })
    finally:
        if suspender is not None and suspender.is_alive():
            suspender.join(timeout=40)
        client.close()


if __name__ == "__main__":
    main()
