"""Failure-path integration test for file-backed trace code streaming."""
import ctypes
import glob
import os
import tempfile
import threading
import time

from test_trace_basic_blocks import Client, TARGET


def terminate_owned_target(pid):
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    handle = kernel32.OpenProcess(0x0001 | 0x00100000, False, pid)  # TERMINATE | SYNCHRONIZE
    if handle:
        kernel32.TerminateProcess(handle, 0)
        kernel32.WaitForSingleObject(handle, 5000)
        kernel32.CloseHandle(handle)


def initialize(client):
    client.call("initialize", {
        "protocolVersion": "2024-11-05",
        "clientInfo": {"name": "trace-code-stream-failure-test", "version": "1"},
        "capabilities": {},
    })


def main():
    first = Client()
    second = None
    target_pid = 0
    output_path = os.path.join(
        tempfile.gettempdir(), f"veh-trace-crash-{os.getpid()}-{time.time_ns()}.vtc")
    trace_errors = []
    try:
        initialize(first)
        launch = first.tool("veh_launch", {"program": TARGET, "stopOnEntry": True})
        assert launch.get("success"), launch
        target_pid = launch["pid"]
        breakpoint = first.tool("veh_set_function_breakpoint", {"name": "TraceCoverageTarget"})
        assert breakpoint.get("success"), breakpoint
        stop = first.tool("veh_continue", {"wait": True, "timeout": 10}, timeout=15)
        assert stop.get("reason") == "breakpoint", stop
        thread_id = stop["threadId"]
        registers = first.tool("veh_registers", {"threadId": thread_id})["registers"]
        ip_name = "eip" if "eip" in registers else "rip"

        loop = first.tool("veh_allocate_memory", {"size": 4096, "protection": "rwx"})
        assert loop.get("success"), loop
        loop_start = int(loop["address"], 0)
        assert first.tool("veh_write_memory", {
            "address": hex(loop_start), "data": "90 eb fd",
        }).get("success")
        assert first.tool("veh_set_register", {
            "threadId": thread_id, "name": ip_name, "value": hex(loop_start),
        }).get("success")

        def run_trace():
            try:
                first.tool("veh_trace_basic_blocks", {
                    "threadId": thread_id, "start": hex(loop_start), "end": hex(loop_start + 3),
                    "max_steps": 5000000, "timeout_ms": 1000, "stack_bytes": 0,
                    "collect_code": True, "max_code_bytes": 400 * 1024 * 1024,
                    "code_output": "file", "code_output_path": output_path,
                    "code_chunk_bytes": 256 * 1024,
                }, timeout=20)
            except Exception as error:  # expected when the MCP process is killed
                trace_errors.append(str(error))

        trace_thread = threading.Thread(target=run_trace)
        trace_thread.start()
        deadline = time.time() + 5
        while time.time() < deadline and not glob.glob(output_path + ".partial-*"):
            time.sleep(0.01)
        assert glob.glob(output_path + ".partial-*"), "stream partial file was not created"

        first.proc.kill()
        first.proc.wait(timeout=5)
        trace_thread.join(timeout=5)
        assert not trace_thread.is_alive(), "trace caller did not observe MCP termination"

        deadline = time.time() + 5
        while time.time() < deadline and glob.glob(output_path + ".partial-*"):
            time.sleep(0.05)
        assert not glob.glob(output_path + ".partial-*"), "crashed MCP left a partial artifact"
        assert not os.path.exists(output_path), "crashed stream published a final artifact"

        # The DLL writer must observe the broken data pipe and release the trace
        # without wedging its control server. A new MCP can reconnect and terminate.
        time.sleep(3)
        second = Client()
        initialize(second)
        attached = second.tool("veh_attach", {"pid": target_pid}, timeout=15)
        assert attached.get("success"), attached
        terminated = second.tool("veh_terminate", timeout=10)
        assert terminated.get("success"), terminated
        target_pid = 0
        print({"mcp_exit_observed": bool(trace_errors), "partial_cleaned": True,
               "reconnect_after_broken_stream": True})
    finally:
        if second is not None:
            second.close()
        if first.proc.poll() is None:
            first.close()
        if target_pid:
            terminate_owned_target(target_pid)
        for path in glob.glob(output_path + "*"):
            try:
                os.remove(path)
            except OSError:
                pass


if __name__ == "__main__":
    main()
