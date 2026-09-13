"""Timeout-aware DAP stdio client shared by integration tests."""
from collections import deque
import json
import os
import queue
import subprocess
import threading
import time


def _terminate_owned_descendants(parent_pid, expected_paths):
    """Terminate only descendants whose executable exactly matches a launched target."""
    if os.name != "nt" or not expected_paths:
        return
    import ctypes
    from ctypes import wintypes

    class ProcessEntry(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD), ("th32DefaultHeapID", ctypes.c_size_t),
            ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", wintypes.LONG),
            ("dwFlags", wintypes.DWORD), ("szExeFile", wintypes.WCHAR * 260),
        ]

    kernel32 = ctypes.windll.kernel32
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.OpenProcess.restype = wintypes.HANDLE
    snapshot = kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
    if snapshot == wintypes.HANDLE(-1).value:
        return
    processes = {}
    entry = ProcessEntry()
    entry.dwSize = ctypes.sizeof(entry)
    try:
        present = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
        while present:
            processes[entry.th32ProcessID] = entry.th32ParentProcessID
            present = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snapshot)

    expected = {os.path.normcase(os.path.abspath(path)) for path in expected_paths}
    for process_id, direct_parent in processes.items():
        ancestor = direct_parent
        visited = set()
        while ancestor and ancestor not in visited and ancestor != parent_pid:
            visited.add(ancestor)
            ancestor = processes.get(ancestor, 0)
        if ancestor != parent_pid:
            continue
        handle = kernel32.OpenProcess(0x00100000 | 0x00001000 | 0x00000001, False, process_id)
        if not handle:
            continue
        try:
            size = wintypes.DWORD(32768)
            buffer = ctypes.create_unicode_buffer(size.value)
            if not kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
                continue
            if os.path.normcase(os.path.abspath(buffer.value)) not in expected:
                continue
            if kernel32.TerminateProcess(handle, 0):
                kernel32.WaitForSingleObject(handle, 5000)
        finally:
            kernel32.CloseHandle(handle)


class DapClient:
    def __init__(self, adapter, *adapter_args, stderr_lines=200):
        self.proc = subprocess.Popen(
            [adapter, *adapter_args], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, bufsize=0,
        )
        self.seq = 0
        self.messages = queue.Queue()
        self.backlog = deque()
        self.stderr = deque(maxlen=stderr_lines)
        self.target_paths = set()
        self.reader = threading.Thread(target=self._read_messages, daemon=True)
        self.stderr_reader = threading.Thread(target=self._read_stderr, daemon=True)
        self.reader.start()
        self.stderr_reader.start()

    def _read_messages(self):
        try:
            while True:
                headers = {}
                while True:
                    line = self.proc.stdout.readline()
                    if not line:
                        return
                    if line in (b"\r\n", b"\n"):
                        break
                    if b":" in line:
                        name, value = line.decode("ascii", errors="replace").split(":", 1)
                        headers[name.lower()] = value.strip()
                length = int(headers.get("content-length", "0"))
                if length <= 0:
                    continue
                body = bytearray()
                while len(body) < length:
                    chunk = self.proc.stdout.read(length - len(body))
                    if not chunk:
                        return
                    body.extend(chunk)
                self.messages.put(json.loads(body))
        except Exception as error:
            self.messages.put({"_client_error": str(error)})
        finally:
            self.messages.put(None)

    def _read_stderr(self):
        for line in self.proc.stderr:
            self.stderr.append(line.decode(errors="replace").rstrip())

    def send(self, command, arguments=None):
        if self.proc.poll() is not None:
            raise RuntimeError(f"adapter exited ({self.proc.returncode}): {self.stderr_tail()}")
        self.seq += 1
        if command == "launch" and isinstance(arguments, dict) and arguments.get("program"):
            self.target_paths.add(arguments["program"])
        message = {"seq": self.seq, "type": "request", "command": command}
        if arguments is not None:
            message["arguments"] = arguments
        body = json.dumps(message, separators=(",", ":")).encode()
        self.proc.stdin.write(f"Content-Length: {len(body)}\r\n\r\n".encode() + body)
        self.proc.stdin.flush()
        return self.seq

    def wait_for(self, predicate, timeout=15):
        for index, message in enumerate(self.backlog):
            if predicate(message):
                del self.backlog[index]
                return message
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"DAP response timed out after {timeout}s")
            try:
                message = self.messages.get(timeout=remaining)
            except queue.Empty as error:
                raise TimeoutError(f"DAP response timed out after {timeout}s") from error
            if message is None:
                raise RuntimeError(f"adapter exited while waiting: {self.stderr_tail()}")
            if "_client_error" in message:
                raise RuntimeError(message["_client_error"])
            if predicate(message):
                return message
            self.backlog.append(message)

    def request(self, command, arguments=None, timeout=15):
        request_seq = self.send(command, arguments)
        return self.wait_for(
            lambda item: item.get("type") == "response" and
            item.get("request_seq") == request_seq and item.get("command") == command,
            timeout,
        )

    def event(self, name, timeout=15, predicate=None):
        return self.wait_for(
            lambda item: item.get("type") == "event" and item.get("event") == name and
            (predicate is None or predicate(item)), timeout,
        )

    def initialize(self):
        response = self.request("initialize", {"adapterID": "veh", "clientID": "test"})
        if not response.get("success"):
            raise AssertionError(response)
        return response

    def stderr_tail(self):
        return "\n".join(self.stderr)

    def close(self, terminate_debuggee=True):
        try:
            if self.proc.poll() is None:
                try:
                    self.request("disconnect", {"terminateDebuggee": terminate_debuggee}, timeout=3)
                except Exception:
                    pass
        finally:
            if self.proc.poll() is None:
                self.proc.terminate()
                try:
                    self.proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.proc.kill()
                    self.proc.wait(timeout=5)
            _terminate_owned_descendants(self.proc.pid, self.target_paths)
            self.reader.join(timeout=1)
            self.stderr_reader.join(timeout=1)
