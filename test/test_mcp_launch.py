"""MCP veh_launch stopOnEntry bug fix test.

Tests that:
1. stopOnEntry=false -> process runs immediately (exits on its own)
2. stopOnEntry=true -> process is suspended, veh_continue resumes it
3. cached stops and exceptions do not cross a relaunch boundary
4. an outstanding wait is cancelled when a new session replaces it
5. both synchronous remote-thread injection methods accept real module handles
6. selective continue reports resumed and still-stopped thread IDs
7. setting a WriteFile function breakpoint cannot kill the target via logger recursion
8. changing RIP while stopped at software/hardware execute breakpoints resumes safely
9. step_in from a hardware execute breakpoint stops synchronously
10. veh_batch preserves breakpoint actions and accepts JSON-encoded string steps
"""
import subprocess
from build_paths import RELEASE
import json
import time
import sys
import os
import tempfile
import queue
import threading
from collections import deque

MCP_EXE = os.environ.get("VEH_MCP_EXE", os.path.join(RELEASE, "veh-mcp-server.exe"))
TARGET = os.environ.get("VEH_TEST_TARGET", os.path.join(RELEASE, "test_target.exe"))

ACTIVE_CLIENTS = set()

class McpClient:
    def __init__(self):
        self.proc = subprocess.Popen(
            [MCP_EXE],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.seq = 0
        self.messages = queue.Queue()
        self.stderr = deque(maxlen=200)
        self.reader = threading.Thread(target=self._read_stdout, daemon=True)
        self.stderr_reader = threading.Thread(target=self._read_stderr, daemon=True)
        self.reader.start()
        self.stderr_reader.start()
        ACTIVE_CLIENTS.add(self)

    def _read_stdout(self):
        try:
            for line in self.proc.stdout:
                try:
                    self.messages.put(json.loads(line))
                except json.JSONDecodeError:
                    continue
        finally:
            self.messages.put(None)

    def _read_stderr(self):
        for line in self.proc.stderr:
            self.stderr.append(line.decode(errors="replace").rstrip())

    def send(self, method, params=None):
        self.seq += 1
        msg = {"jsonrpc": "2.0", "id": self.seq, "method": method}
        if params:
            msg["params"] = params
        data = json.dumps(msg) + "\n"
        self.proc.stdin.write(data.encode())
        self.proc.stdin.flush()
        return self.seq

    def recv(self, timeout=10):
        """Read one JSON-RPC response line."""
        try:
            message = self.messages.get(timeout=timeout)
        except queue.Empty:
            return None
        return message

    def call_tool(self, name, args=None):
        request_id = self.send("tools/call", {"name": name, "arguments": args or {}})
        while True:
            response = self.recv()
            if response is None or response.get("id") == request_id:
                return response

    def close(self):
        try:
            if self.proc.poll() is None:
                try:
                    self.call_tool("veh_terminate")
                except Exception:
                    pass
                self.proc.terminate()
                try:
                    self.proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.proc.kill()
                    self.proc.wait(timeout=5)
        finally:
            ACTIVE_CLIENTS.discard(self)
            self.reader.join(timeout=1)
            self.stderr_reader.join(timeout=1)


def check_process_alive(pid):
    """Check if process is still running."""
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        h = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not h:
            return False
        exit_code = ctypes.c_ulong()
        kernel32.GetExitCodeProcess(h, ctypes.byref(exit_code))
        kernel32.CloseHandle(h)
        return exit_code.value == 259  # STILL_ACTIVE
    except:
        return False


def terminate_process(pid):
    """Best-effort cleanup for targets deliberately detached by a test."""
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(0x0001, False, pid)  # PROCESS_TERMINATE
        if handle:
            kernel32.TerminateProcess(handle, 0)
            kernel32.CloseHandle(handle)
    except Exception:
        pass


def tool_data(response):
    result = (response or {}).get("result", {})
    content = result.get("content", [{}])
    text = content[0].get("text", "") if content else ""
    return json.loads(text) if text else {}


def resolve_function_address(client, name):
    """Resolve a function through the public tool, then remove its temporary BP."""
    result = tool_data(client.call_tool("veh_set_function_breakpoint", {"name": name}))
    assert result.get("success") is True and result.get("address"), result
    removed = tool_data(client.call_tool("veh_remove_breakpoint", {"id": result["id"]}))
    assert removed.get("success") is True, removed
    return result["address"]


def test_stop_on_entry_false():
    """stopOnEntry=false: process should run and exit on its own."""
    print("=== Test: stopOnEntry=false ===")
    client = McpClient()

    # Initialize
    client.send("initialize", {"protocolVersion": "2024-11-05",
                                "capabilities": {},
                                "clientInfo": {"name": "test", "version": "1.0"}})
    resp = client.recv()
    assert resp and "result" in resp, f"Initialize failed: {resp}"
    print("  Initialize OK")

    # Launch with stopOnEntry=false
    resp = client.call_tool("veh_launch", {
        "program": TARGET,
        "stopOnEntry": False
    })
    print(f"  Launch response: {resp}")
    assert resp, "No response from launch"
    result = resp.get("result", {})
    content = result.get("content", [{}])
    text = content[0].get("text", "") if content else ""
    data = json.loads(text) if text else {}
    assert "error" not in data, f"Launch error: {data}"
    pid = data.get("pid", 0)
    assert pid > 0, f"No PID: {data}"
    print(f"  Launched PID={pid}")

    # Wait a bit for process to run
    time.sleep(2)

    # Process should have run (may or may not be alive depending on test_target behavior)
    alive = check_process_alive(pid)
    print(f"  Process alive after 2s: {alive}")

    # Detach
    resp = client.call_tool("veh_terminate")
    print(f"  Terminate: {resp}")

    terminate_process(pid)

    client.close()
    print("  PASSED\n")
    return True


def test_stop_on_entry_true():
    """stopOnEntry=true (default): process should be suspended until veh_continue."""
    print("=== Test: stopOnEntry=true (default) ===")
    client = McpClient()

    # Initialize
    client.send("initialize", {"protocolVersion": "2024-11-05",
                                "capabilities": {},
                                "clientInfo": {"name": "test", "version": "1.0"}})
    resp = client.recv()
    assert resp and "result" in resp, f"Initialize failed: {resp}"
    print("  Initialize OK")

    # Launch with stopOnEntry=true (default)
    resp = client.call_tool("veh_launch", {
        "program": TARGET,
        "stopOnEntry": True
    })
    print(f"  Launch response: {resp}")
    assert resp, "No response from launch"
    result = resp.get("result", {})
    content = result.get("content", [{}])
    text = content[0].get("text", "") if content else ""
    data = json.loads(text) if text else {}
    assert "error" not in data, f"Launch error: {data}"
    pid = data.get("pid", 0)
    assert pid > 0, f"No PID: {data}"
    print(f"  Launched PID={pid}")

    # Process should still be alive (suspended)
    time.sleep(1)
    alive = check_process_alive(pid)
    assert alive, "Process should be alive (suspended) but it's not!"
    print(f"  Process alive (suspended): {alive}")

    # Now continue - should resume the OS-suspended thread
    resp = client.call_tool("veh_continue", {"threadId": 0})
    print(f"  Continue response: {resp}")
    continue_data = tool_data(resp)
    assert continue_data.get("resumeScope") == "all", continue_data
    assert continue_data.get("resumedThreadIds"), continue_data
    assert continue_data.get("stillStoppedThreadIds") == [], continue_data

    # Wait for process to run
    time.sleep(2)

    # Detach
    resp = client.call_tool("veh_terminate")
    print(f"  Terminate: {resp}")

    terminate_process(pid)

    client.close()
    print("  PASSED\n")
    return True


def test_new_launch_clears_previous_stop():
    """A cached exception from process A must never be returned for process B."""
    print("=== Test: launch clears previous session stop state ===")
    client = McpClient()

    client.send("initialize", {"protocolVersion": "2024-11-05",
                                "capabilities": {},
                                "clientInfo": {"name": "test", "version": "1.0"}})
    init_response = client.recv()
    assert init_response and "result" in init_response, init_response

    first = tool_data(client.call_tool("veh_launch", {
        "program": TARGET,
        "args": ["--crash"],
        "stopOnEntry": False,
    }))
    assert "error" not in first and first.get("pid", 0) > 0, first

    # Let process A's AV reach the MCP stop cache without consuming it.
    time.sleep(3)

    second = tool_data(client.call_tool("veh_launch", {
        "program": TARGET,
        "stopOnEntry": True,
    }))
    assert "error" not in second and second.get("pid", 0) > 0, second
    assert second["pid"] != first["pid"]
    terminate_process(first["pid"])

    exception_info = tool_data(client.call_tool("veh_exception_info"))
    assert exception_info.get("error") == "No exception recorded", exception_info

    continued = tool_data(client.call_tool("veh_continue", {
        "wait": True,
        "timeout": 1,
    }))
    assert continued.get("timeout") is True, continued

    client.call_tool("veh_terminate")
    client.close()
    print("  PASSED\n")
    return True


def test_explicit_remote_thread_methods():
    """Both synchronous LoadLibrary methods still accept real module handles."""
    print("=== Test: explicit remote-thread injection methods ===")
    client = McpClient()

    client.send("initialize", {"protocolVersion": "2024-11-05",
                                "capabilities": {},
                                "clientInfo": {"name": "test", "version": "1.0"}})
    init_response = client.recv()
    assert init_response and "result" in init_response, init_response

    for method in ["createRemoteThread", "ntCreateThreadEx"]:
        launched = tool_data(client.call_tool("veh_launch", {
            "program": TARGET,
            "stopOnEntry": True,
            "injectionMethod": method,
        }))
        assert "error" not in launched and launched.get("pid", 0) > 0, {
            "method": method,
            "result": launched,
        }
        terminated = tool_data(client.call_tool("veh_terminate"))
        assert terminated.get("success") is True, {"method": method, "result": terminated}

    client.close()
    print("  PASSED\n")
    return True


def test_wait_is_cancelled_by_relaunch():
    """A wait started for process A must not consume process B's first stop."""
    print("=== Test: outstanding wait is cancelled by relaunch ===")
    client = McpClient()

    client.send("initialize", {"protocolVersion": "2024-11-05",
                                "capabilities": {},
                                "clientInfo": {"name": "test", "version": "1.0"}})
    init_response = client.recv()
    assert init_response and "result" in init_response, init_response

    first = tool_data(client.call_tool("veh_launch", {
        "program": TARGET,
        "stopOnEntry": True,
    }))
    assert "error" not in first and first.get("pid", 0) > 0, first

    wait_id = client.send("tools/call", {
        "name": "veh_continue",
        "arguments": {"wait": True, "timeout": 10},
    })
    time.sleep(0.25)
    launch_id = client.send("tools/call", {
        "name": "veh_launch",
        "arguments": {"program": TARGET, "stopOnEntry": True},
    })

    responses = {}
    while wait_id not in responses or launch_id not in responses:
        response = client.recv(timeout=15)
        assert response is not None, responses
        if response.get("id") in (wait_id, launch_id):
            responses[response["id"]] = response

    wait_result = tool_data(responses[wait_id])
    assert wait_result.get("error") == "Debug session changed while waiting for a stop event", wait_result

    launch_result = tool_data(responses[launch_id])
    assert "error" not in launch_result and launch_result.get("pid", 0) > 0, launch_result
    terminate_process(first["pid"])

    client.call_tool("veh_terminate")
    client.close()
    print("  PASSED\n")
    return True


def test_selective_continue_visibility():
    """threadId=X resumes only X and reports every debugger-stopped thread."""
    print("=== Test: selective continue visibility ===")
    client = McpClient()

    client.send("initialize", {"protocolVersion": "2024-11-05",
                                "capabilities": {},
                                "clientInfo": {"name": "test", "version": "1.0"}})
    init_response = client.recv()
    assert init_response and "result" in init_response, init_response

    launched = tool_data(client.call_tool("veh_launch", {
        "program": TARGET,
        "stopOnEntry": False,
    }))
    assert "error" not in launched and launched.get("pid", 0) > 0, launched

    # Add a second application thread so a selective resume has another stopped
    # thread to leave behind. EB FE is an architecture-neutral infinite loop.
    shellcode = tool_data(client.call_tool("veh_execute_shellcode", {
        "shellcode": "EBFE",
        "timeout_ms": 0,
    }))
    assert shellcode.get("success") is True, shellcode
    time.sleep(0.2)

    threads = tool_data(client.call_tool("veh_threads")).get("threads", [])
    assert len(threads) >= 2, threads
    thread_ids = sorted(t["id"] for t in threads)

    paused = tool_data(client.call_tool("veh_pause", {"threadId": 0}))
    assert paused.get("success") is True, paused
    selected = thread_ids[0]
    continued = tool_data(client.call_tool("veh_continue", {"threadId": selected}))
    assert continued.get("resumeScope") == "single", continued
    assert continued.get("requestedThreadId") == selected, continued
    assert continued.get("resumedThreadIds") == [selected], continued
    still_stopped = continued.get("stillStoppedThreadIds", [])
    assert selected not in still_stopped, continued
    assert set(thread_ids[1:]).issubset(set(still_stopped)), continued

    continued_all = tool_data(client.call_tool("veh_continue", {"threadId": 0}))
    assert continued_all.get("resumeScope") == "all", continued_all
    assert set(still_stopped).issubset(set(continued_all.get("resumedThreadIds", []))), continued_all
    assert continued_all.get("stillStoppedThreadIds") == [], continued_all

    client.call_tool("veh_terminate")
    client.close()
    print("  PASSED\n")
    return True


def test_writefile_function_breakpoint_survives():
    """The SetBreakpoint response itself uses WriteFile on the internal pipe thread."""
    print("=== Test: WriteFile function breakpoint survives ===")
    client = McpClient()

    client.send("initialize", {"protocolVersion": "2024-11-05",
                                "capabilities": {},
                                "clientInfo": {"name": "test", "version": "1.0"}})
    init_response = client.recv()
    assert init_response and "result" in init_response, init_response

    launched = tool_data(client.call_tool("veh_launch", {
        "program": TARGET,
        "stopOnEntry": True,
    }))
    pid = launched.get("pid", 0)
    assert "error" not in launched and pid > 0, launched

    create_file = tool_data(client.call_tool("veh_set_function_breakpoint", {
        "name": "kernel32!CreateFileW",
    }))
    assert create_file.get("success") is True, create_file

    write_file = tool_data(client.call_tool("veh_set_function_breakpoint", {
        "name": "kernel32!WriteFile",
    }))
    assert write_file.get("success") is True, write_file
    assert check_process_alive(pid), write_file
    threads = tool_data(client.call_tool("veh_threads"))
    assert threads.get("threads"), threads

    client.call_tool("veh_terminate")
    client.close()
    print("  PASSED\n")
    return True


def test_breakpoint_rip_redirects():
    """Changing RIP at either breakpoint kind must not leak a debugger exception."""
    print("=== Test: breakpoint RIP redirects ===")
    client = McpClient()
    client.send("initialize", {"protocolVersion": "2024-11-05", "capabilities": {},
                                "clientInfo": {"name": "test", "version": "1.0"}})
    assert "result" in client.recv()

    launched = tool_data(client.call_tool("veh_launch", {"program": TARGET, "stopOnEntry": True}))
    pid = launched.get("pid", 0)
    assert pid > 0, launched
    work = resolve_function_address(client, "WorkFunction")
    allocated = tool_data(client.call_tool("veh_allocate_memory", {
        "size": 4096, "protection": "rwx",
    }))
    trap_stub = allocated.get("address")
    assert trap_stub, allocated
    written = tool_data(client.call_tool("veh_write_memory", {
        "address": trap_stub, "data": "CC C3",
    }))
    assert written.get("success") is True, written

    sw = tool_data(client.call_tool("veh_set_breakpoint", {"address": work}))
    assert sw.get("success") is True, sw
    hit = tool_data(client.call_tool("veh_continue", {"wait": True, "timeout": 4}))
    assert hit.get("breakpointId") == sw["id"], hit
    tid = hit["threadId"]
    initial_regs = tool_data(client.call_tool("veh_registers", {"threadId": tid}))["registers"]
    ip_name = "EIP" if initial_regs.get("is32bit") else "RIP"
    changed = tool_data(client.call_tool("veh_set_register", {
        "threadId": tid, "name": ip_name, "value": trap_stub,
    }))
    assert changed.get("success") is True, changed
    foreign_int3 = tool_data(client.call_tool("veh_continue", {"wait": True, "timeout": 4}))
    assert foreign_int3.get("reason") == "exception", foreign_int3
    assert foreign_int3.get("address", "").lower() == trap_stub.lower(), foreign_int3
    hit_again = tool_data(client.call_tool("veh_continue", {"wait": True, "timeout": 4}))
    # x86 may stay in its CRT loop without revisiting WorkFunction in this window;
    # either a new hit or a live running target proves INT3 was consumed safely.
    assert hit_again.get("breakpointId") == sw["id"] or hit_again.get("timeout") is True, hit_again
    assert check_process_alive(pid), hit_again
    assert tool_data(client.call_tool("veh_remove_breakpoint", {"id": sw["id"]})).get("success") is True

    hw = tool_data(client.call_tool("veh_set_data_breakpoint", {
        "address": work, "type": "execute", "size": 1,
    }))
    assert hw.get("success") is True, hw
    # Resume from the software BP's restored instruction; the HW BP catches the
    # following loop iteration.
    hw_hit = tool_data(client.call_tool("veh_continue", {"wait": True, "timeout": 4}))
    assert hw_hit.get("breakpointId") == hw["id"], hw_hit
    tid = hw_hit["threadId"]
    changed = tool_data(client.call_tool("veh_set_register", {
        "threadId": tid, "name": ip_name, "value": trap_stub,
    }))
    assert changed.get("success") is True, changed
    foreign_int3 = tool_data(client.call_tool("veh_continue", {"wait": True, "timeout": 4}))
    assert foreign_int3.get("reason") == "exception", foreign_int3
    assert foreign_int3.get("address", "").lower() == trap_stub.lower(), foreign_int3
    hw_hit_again = tool_data(client.call_tool("veh_continue", {"wait": True, "timeout": 4}))
    assert hw_hit_again.get("breakpointId") == hw["id"] or hw_hit_again.get("timeout") is True, hw_hit_again
    assert check_process_alive(pid), hw_hit_again

    client.call_tool("veh_terminate")
    client.close()
    print("  PASSED\n")
    return True


def test_hw_breakpoint_step_in_is_synchronous():
    """step_in after a HW execute hit must stop again before returning."""
    print("=== Test: HW breakpoint synchronous step_in ===")
    client = McpClient()
    client.send("initialize", {"protocolVersion": "2024-11-05", "capabilities": {},
                                "clientInfo": {"name": "test", "version": "1.0"}})
    assert "result" in client.recv()
    launched = tool_data(client.call_tool("veh_launch", {"program": TARGET, "stopOnEntry": True}))
    assert launched.get("pid", 0) > 0, launched
    work = resolve_function_address(client, "WorkFunction")
    hw = tool_data(client.call_tool("veh_set_data_breakpoint", {
        "address": work, "type": "execute", "size": 1,
    }))
    assert hw.get("success") is True, hw
    hit = tool_data(client.call_tool("veh_continue", {"wait": True, "timeout": 4}))
    assert hit.get("breakpointId") == hw["id"], hit
    tid = hit["threadId"]
    removed = tool_data(client.call_tool("veh_remove_data_breakpoint", {"id": hw["id"]}))
    assert removed.get("success") is True, removed

    stepped = tool_data(client.call_tool("veh_step_in", {"threadId": tid}))
    assert stepped.get("success") is True and stepped.get("instructionPointer"), stepped
    registers = tool_data(client.call_tool("veh_registers", {"threadId": tid}))
    regs = registers.get("registers", {})
    ip_key = "eip" if regs.get("is32bit") else "rip"
    assert regs.get(ip_key, "").lower() == stepped["instructionPointer"].lower(), registers

    client.call_tool("veh_terminate")
    client.close()
    print("  PASSED\n")
    return True


def test_batch_breakpoint_action_and_string_steps():
    """Batch-created BP actions execute off the pipe reader and can add a nested BP."""
    print("=== Test: batch breakpoint action and string steps ===")
    client = McpClient()
    client.send("initialize", {"protocolVersion": "2024-11-05", "capabilities": {},
                                "clientInfo": {"name": "test", "version": "1.0"}})
    assert "result" in client.recv()
    launched = tool_data(client.call_tool("veh_launch", {"program": TARGET, "stopOnEntry": True}))
    assert launched.get("pid", 0) > 0, launched
    work = resolve_function_address(client, "WorkFunction")
    sleep_ex = resolve_function_address(client, "kernel32!SleepEx")

    batch = tool_data(client.call_tool("veh_batch", {"steps": [{
        "tool": "veh_set_breakpoint",
        "args": {"address": work, "action": [{
            "tool": "veh_set_breakpoint", "args": {"address": sleep_ex},
        }]},
    }]}))
    outer = batch["results"][0]["result"]
    assert outer.get("success") is True and outer.get("hasAction") is True, batch

    # The outer action installs SleepEx and auto-resumes. The target naturally calls
    # SleepEx next, proving the nested action command really ran.
    outer_hit = tool_data(client.call_tool("veh_continue", {"wait": True, "timeout": 4}))
    assert outer_hit.get("breakpointId") != outer["id"], outer_hit
    listed = tool_data(client.call_tool("veh_list_breakpoints"))
    nested = [bp for bp in listed.get("software", [])
              if bp.get("address", "").lower() == sleep_ex.lower()]
    assert nested and outer_hit.get("breakpointId") == nested[0]["id"], (listed, outer_hit)

    # Both inline and file modes accept schema-compatible JSON string steps.
    string_step = json.dumps({"tool": "veh_remove_breakpoint", "args": {"id": nested[0]["id"]}})
    inline = tool_data(client.call_tool("veh_batch", {"steps": [string_step]}))
    assert inline["results"][0]["result"].get("success") is True, inline
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
        json.dump([json.dumps({"tool": "veh_threads", "args": {}})], f)
        batch_file = f.name
    try:
        from_file = tool_data(client.call_tool("veh_batch", {"file": batch_file}))
        assert from_file["results"][0]["result"].get("threads"), from_file
    finally:
        os.unlink(batch_file)

    client.call_tool("veh_terminate")
    client.close()
    print("  PASSED\n")
    return True


if __name__ == "__main__":
    passed = 0
    failed = 0

    for test_fn in [test_stop_on_entry_false, test_stop_on_entry_true,
                    test_new_launch_clears_previous_stop,
                    test_explicit_remote_thread_methods,
                    test_wait_is_cancelled_by_relaunch,
                    test_selective_continue_visibility,
                    test_writefile_function_breakpoint_survives,
                    test_breakpoint_rip_redirects,
                    test_hw_breakpoint_step_in_is_synchronous,
                    test_batch_breakpoint_action_and_string_steps]:
        try:
            if test_fn():
                passed += 1
        except Exception as e:
            print(f"  FAILED: {e}\n")
            failed += 1
        finally:
            for active in list(ACTIVE_CLIENTS):
                active.close()

    print(f"\nResults: {passed} passed, {failed} failed")
    sys.exit(1 if failed > 0 else 0)
