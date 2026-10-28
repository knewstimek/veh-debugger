"""Localhost TLS/resident regression using host-only synthetic protocol peers."""
import ctypes
from ctypes import wintypes
import hashlib
import hmac
import json
import os
from pathlib import Path
import queue
import secrets
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
from unittest.mock import patch

from build_paths import RELEASE
from mcp_test_client import McpClient

BIN = Path(RELEASE)
CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
MAGIC = 0x52484556
DOMAIN = b"VEH-REMOTE-CLIENT-v1"
KERNEL = ctypes.WinDLL("kernel32", use_last_error=True)
KERNEL.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
KERNEL.OpenProcess.restype = wintypes.HANDLE
KERNEL.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
KERNEL.TerminateProcess.argtypes = (wintypes.HANDLE, wintypes.UINT)
KERNEL.CloseHandle.argtypes = (wintypes.HANDLE,)
KERNEL.OpenThread.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
KERNEL.OpenThread.restype = wintypes.HANDLE
KERNEL.GetProcessIdOfThread.argtypes = (wintypes.HANDLE,)
KERNEL.GetProcessIdOfThread.restype = wintypes.DWORD
KERNEL.QueryFullProcessImageNameW.argtypes = (wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD))


def powershell(script, directory):
    environment = dict(os.environ, VEH_TEST_TEMP=str(directory))
    completed = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        env=environment, capture_output=True, timeout=30,
        creationflags=CREATE_NO_WINDOW)
    if completed.returncode:
        raise RuntimeError("certificate/private fixture operation failed")
    return completed.stdout.decode("utf-8-sig").strip()


def exact(connection, size, seconds=10):
    deadline = time.monotonic() + seconds
    result = bytearray()
    while len(result) < size:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("TLS read deadline")
        connection.settimeout(remaining)
        part = connection.recv(size - len(result))
        if not part:
            raise EOFError("TLS connection closed")
        result.extend(part)
    return bytes(result)


def control(connection, kind, payload=b""):
    assert len(payload) <= 65536
    connection.sendall(struct.pack("<IIII", MAGIC, 1, kind, len(payload)) + payload)


def read_control(connection, kind):
    magic, version, actual, size = struct.unpack("<IIII", exact(connection, 16))
    assert (magic, version, actual) == (MAGIC, 1, kind), "invalid control header"
    assert size <= 65536, "oversized control payload"
    return exact(connection, size)


def connect(port, pin):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection(("127.0.0.1", port), timeout=10)
    try:
        peer = context.wrap_socket(raw, server_hostname="localhost")
    except BaseException:
        raw.close()
        raise
    assert hashlib.sha256(peer.getpeercert(binary_form=True)).hexdigest() == pin, "certificate pin"
    return peer


def authenticate(peer, token, proof=None):
    nonce = read_control(peer, 1)
    assert len(nonce) == 32, "nonce width"
    generated = hmac.digest(token, DOMAIN + nonce, "sha256")
    control(peer, 2, generated if proof is None else proof)
    assert read_control(peer, 3) == b"", "auth completion"
    return generated


def raw_open(port, pin, token, request):
    peer = connect(port, pin)
    try:
        authenticate(peer, token)
        control(peer, 4, json.dumps(request, separators=(",", ":")).encode())
        result = json.loads(read_control(peer, 5))
        assert result.get("success"), "resident work open"
        command, size = struct.unpack("<II", exact(peer, 8))
        assert (command, size) == (0x1000, 0), "ready event"
        return peer, result
    except BaseException:
        peer.close()
        raise


def raw_threads(peer):
    peer.sendall(struct.pack("<II", 0x20, 0))
    for _ in range(16):
        command, size = struct.unpack("<II", exact(peer, 8))
        assert size <= 65536, "fixture IPC size"
        payload = exact(peer, size)
        if command == 0x20:
            status, count = struct.unpack_from("<II", payload)
            assert (status, count) == (0, 1), "raw thread metadata"
            assert struct.unpack_from("<I", payload, 8)[0] == 77, "raw thread identity"
            return payload
    raise AssertionError("thread reply missing")


class DropWorkReplyProxy:
    """Forward TLS unchanged, dropping only the first OpenWork reply."""
    def __init__(self, upstream):
        self.upstream = upstream
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(3)
        self.listener.settimeout(0.2)
        self.port = self.listener.getsockname()[1]
        self.stop = threading.Event()
        self.dropped = threading.Event()
        self.rejected_retry_handshake = threading.Event()
        self.sockets = []
        self.lock = threading.Lock()
        self.thread = threading.Thread(target=self._serve)

    def __enter__(self):
        self.thread.start()
        return self

    def _track(self, connection):
        with self.lock:
            self.sockets.append(connection)

    def _close(self, connection):
        try:
            connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        connection.close()

    def _serve(self):
        while not self.stop.is_set():
            try:
                client, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            backend = None
            sender = None
            try:
                self._track(client)
                if self.dropped.is_set() and not self.rejected_retry_handshake.is_set():
                    self.rejected_retry_handshake.set()
                    continue  # Failed retry before OpenWork must preserve earlier uncertainty.
                backend = socket.create_connection(("127.0.0.1", self.upstream), timeout=10)
                self._track(backend)
                def forward_requests():
                    try:
                        while not self.stop.is_set():
                            data = client.recv(65536)
                            if not data:
                                break
                            backend.sendall(data)
                    except OSError:
                        pass
                    finally:
                        self._close(backend)
                sender = threading.Thread(target=forward_requests)
                sender.start()
                application_records = 0
                while not self.stop.is_set():
                    header = exact(backend, 5)
                    payload = exact(backend, int.from_bytes(header[3:5], "big"))
                    if header[0] == 23:
                        application_records += 1
                    # TLS1.2 application records: challenge header, nonce, auth
                    # completion, then Work header. No plaintext or token is read.
                    if not self.dropped.is_set() and application_records == 4:
                        self.dropped.set()
                        break
                    client.sendall(header + payload)
            except (OSError, EOFError, TimeoutError):
                pass
            finally:
                self._close(client)
                if backend:
                    self._close(backend)
                if sender:
                    sender.join(timeout=5)
                    assert not sender.is_alive(), "proxy request worker remains"

    def __exit__(self, *_):
        self.stop.set()
        self.listener.close()
        with self.lock:
            for connection in self.sockets:
                self._close(connection)
        self.thread.join(timeout=5)
        assert not self.thread.is_alive(), "proxy server remains"


def wait_file(path, seconds=5):
    deadline = time.monotonic() + seconds
    while not path.exists():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("launched process completion")
        # Event/deadline wait yields immediately when the condition becomes visible.
        threading.Event().wait(min(0.02, remaining))


def owned_handle(pid, executable, parent, directory):
    image = ctypes.create_unicode_buffer(32768)
    size = wintypes.DWORD(len(image))
    handle = KERNEL.OpenProcess(0x00100000 | 0x1000 | 0x0001, False, pid)
    assert handle, "owned process handle"
    try:
        assert KERNEL.QueryFullProcessImageNameW(handle, 0, image, ctypes.byref(size))
        assert Path(image.value).resolve() == Path(executable).resolve(), "owned executable mismatch"
        actual_parent = int(powershell(
            f"(Get-CimInstance Win32_Process -Filter 'ProcessId={pid}').ParentProcessId", directory))
        assert actual_parent == parent, "owned parent chain mismatch"
        return handle
    except BaseException:
        KERNEL.CloseHandle(handle)
        raise


def lifecycle_checks(client, runner, directory, target_handles, port, pin, token):
    seen = set()
    def attach(alias, pid):
        result = client.tool("veh_attach", {"backend": alias, "pid": pid}, timeout=25)
        assert result.get("success"), result
        agent = int(client.tool("veh_threads")["threads"][0]["name"].split(":")[1])
        assert agent not in seen, "retiring/dead agent reused"
        seen.add(agent)
        return agent

    # No acknowledgement, then a late acknowledgement, while the reaper may
    # still be waiting for earlier agents. None may poison a new attach.
    for alias, pid in (("silent", 424250), ("late", 424251)):
        attach(alias, pid)
        for _ in range(2):
            assert client.tool("veh_detach").get("success")
            threading.Event().wait(0.5)
            attach(alias, pid)
        assert client.tool("veh_detach").get("success")

    agent = attach("silent", 424252)
    handle = owned_handle(agent, BIN / "guest_backend_fixture.exe", runner.pid, directory)
    try:
        assert KERNEL.TerminateProcess(handle, 1)
        assert KERNEL.WaitForSingleObject(handle, 5000) == 0
        attach("silent", 424252)
        assert client.tool("veh_detach").get("success")
    finally:
        KERNEL.CloseHandle(handle)

    # A dead agent must not make the resident job kill its launched host target.
    marker, release = directory / "agent-death.txt", directory / "release.txt"
    code = ("from pathlib import Path;import time;Path(" + repr(str(marker)) + ").write_text('running');"
            + "\nwhile not Path(" + repr(str(release)) + ").exists():time.sleep(.02)")
    launched = client.tool("veh_launch", {
        "backend": "host", "program": sys.executable, "args": ["-c", code], "stopOnEntry": True}, timeout=25)
    assert launched.get("success"), launched
    assert launched["addressBits"] == struct.calcsize("P") * 8, launched
    assert launched["mainThreadId"] > 0, launched
    initial = KERNEL.OpenThread(0x0800, False, launched["mainThreadId"])
    assert initial, "initial thread must exist while stopOnEntry holds it"
    try:
        assert KERNEL.GetProcessIdOfThread(initial) == launched["pid"], launched
    finally:
        KERNEL.CloseHandle(initial)
    target = owned_handle(launched["pid"], sys.executable, runner.pid, directory)
    target_handles.append(target)
    assert not marker.exists()
    agent = int(client.tool("veh_threads")["threads"][0]["name"].split(":")[1])
    handle = owned_handle(agent, BIN / "guest_backend_fixture.exe", runner.pid, directory)
    try:
        assert KERNEL.TerminateProcess(handle, 1)
        assert KERNEL.WaitForSingleObject(handle, 5000) == 0
    finally:
        KERNEL.CloseHandle(handle)
    wait_file(marker)
    attach("host", launched["pid"])
    assert client.tool("veh_detach").get("success")
    release.write_text("exit", encoding="ascii")
    assert KERNEL.WaitForSingleObject(target, 5000) == 0


    # A retired launch ID must remain non-replayable after agent death, even
    # when the original target survives and the work has left the registry.
    marker, release = directory / "retired-launch.txt", directory / "retired-release.txt"
    request = {"backend": "host", "operation": "launch", "target_scope": "host", "pid": 0,
               "request_id": secrets.token_hex(32), "launch": {"program": sys.executable,
               "args": ["-c", "from pathlib import Path;import time;Path(" + repr(str(marker)) +
                        ").write_text('running');\nwhile not Path(" + repr(str(release)) + ").exists():time.sleep(.02)"],
               "stopOnEntry": True}}
    peer, work = raw_open(port, pin, token, request)
    try:
        payload = raw_threads(peer)
        agent = int(payload[12:76].split(b"\0", 1)[0].decode().split(":")[1])
        target = owned_handle(work["pid"], sys.executable, runner.pid, directory)
        target_handles.append(target)
        handle = owned_handle(agent, BIN / "guest_backend_fixture.exe", runner.pid, directory)
        try:
            assert KERNEL.TerminateProcess(handle, 1)
            assert KERNEL.WaitForSingleObject(handle, 5000) == 0
        finally:
            KERNEL.CloseHandle(handle)
    finally:
        peer.close()
    wait_file(marker)
    threading.Event().wait(3)
    peer = connect(port, pin)
    try:
        authenticate(peer, token)
        control(peer, 4, json.dumps(request).encode())
        denied = json.loads(read_control(peer, 5))
        assert not denied.get("success") and denied.get("code") == "expired" and denied.get("outcome_unknown"), "retired launch replayed"
    finally:
        peer.close()
    release.write_text("exit", encoding="ascii")
    assert KERNEL.WaitForSingleObject(target, 5000) == 0


def dll_lifecycle_checks(directory, target_handles, clients):
    kernel = KERNEL
    kernel.CreateFileW.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                   ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE)
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.PeekNamedPipe.argtypes = (wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                                     ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p)
    kernel.ReadFile.argtypes = (wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                               ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p)
    kernel.WriteFile.argtypes = kernel.ReadFile.argtypes
    client = McpClient()
    clients.append(client)
    client.initialize()
    result = client.tool("veh_launch", {"program": str(BIN / "test_target.exe"), "stopOnEntry": False})
    assert result.get("success"), result
    target = owned_handle(result["pid"], BIN / "test_target.exe", client.proc.pid, directory)
    target_handles.append(target)
    assert client.tool("veh_detach").get("success")
    pipe = None
    def read(size):
        data = bytearray()
        deadline = time.monotonic() + 5
        while len(data) < size:
            available = wintypes.DWORD()
            assert kernel.PeekNamedPipe(pipe, None, 0, None, ctypes.byref(available), None), "response discarded before read"
            if available.value:
                count = min(size - len(data), available.value)
                buffer = ctypes.create_string_buffer(count)
                done = wintypes.DWORD()
                assert kernel.ReadFile(pipe, buffer, count, ctypes.byref(done), None) and done.value
                data.extend(buffer.raw[:done.value])
            else:
                assert time.monotonic() < deadline, "pipe response deadline"
                threading.Event().wait(.01)
        return bytes(data)
    def open_pipe():
        deadline = time.monotonic() + 5
        while True:
            handle = kernel.CreateFileW(r"\\.\pipe\dotnet-diagnostic-" + str(result["pid"]),
                                       0xC0000000, 0, None, 3, 0, None)
            if handle != ctypes.c_void_p(-1).value:
                return handle
            assert time.monotonic() < deadline, "DLL did not accept reconnect"
            threading.Event().wait(.01)
    def ready():
        for _ in range(16):
            command, size = struct.unpack("<II", read(8))
            if size:
                read(size)
            if command == 0x1000:
                return
        raise AssertionError("DLL Ready missing")
    def send(command):
        packet = ctypes.create_string_buffer(struct.pack("<II", command, 0))
        done = wintypes.DWORD()
        assert kernel.WriteFile(pipe, packet, 8, ctypes.byref(done), None) and done.value == 8
    def acknowledgement(expected):
        for _ in range(16):
            command, size = struct.unpack("<II", read(8))
            payload = read(size) if size else b""
            if command == expected:
                assert payload == struct.pack("<I", 0)
                return
        raise AssertionError("DLL lifecycle acknowledgement missing")
    try:
        for command in (0xF0, 0xFF):
            pipe = open_pipe()
            ready()
            send(command)
            threading.Event().wait(.2)  # Deliberately read after the old disconnect point.
            acknowledgement(command)
            kernel.CloseHandle(pipe)
            pipe = None
    finally:
        if pipe is not None:
            kernel.CloseHandle(pipe)


def run():
    runner = None
    clients = []
    target_handles = []
    certificate = None
    runner_lines = queue.Queue()
    checks = 0

    def passed(label):
        nonlocal checks
        checks += 1
        print("PASS " + label, flush=True)

    with tempfile.TemporaryDirectory(prefix="veh-tls-check-") as temporary:
        directory = Path(temporary)
        try:
            for name in ("veh-remote-runner.exe", "veh-mcp-server.exe", "guest_backend_fixture.exe"):
                assert (BIN / name).is_file(), "required executable missing"
            token = secrets.token_bytes(32)
            token_path = directory / "token.txt"
            token_path.write_bytes(token.hex().encode() + b"\r\n")
            fixture = powershell("""
$ErrorActionPreference='Stop'
$p=Join-Path $env:VEH_TEST_TEMP 'token.txt'
$acl=New-Object System.Security.AccessControl.FileSecurity
$acl.SetAccessRuleProtection($true,$false)
$user=[System.Security.Principal.WindowsIdentity]::GetCurrent().User
$acl.SetOwner($user)
foreach($sid in @($user.Value,'S-1-5-18','S-1-5-32-544')){
 $identity=New-Object System.Security.Principal.SecurityIdentifier($sid)
 $rule=New-Object System.Security.AccessControl.FileSystemAccessRule($identity,'FullControl','Allow')
 $acl.AddAccessRule($rule)
}
Set-Acl -LiteralPath $p -AclObject $acl
$cert=New-SelfSignedCertificate -DnsName localhost -Type SSLServerAuthentication -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddDays(1) -FriendlyName ('VEH localhost test '+[guid]::NewGuid())
$hash=[System.Security.Cryptography.SHA256]::Create()
try{$pin=([BitConverter]::ToString($hash.ComputeHash($cert.RawData))).Replace('-','').ToLowerInvariant()}finally{$hash.Dispose()}
@{thumbprint=$cert.Thumbprint;pin=$pin}|ConvertTo-Json -Compress
""", directory)
            metadata = json.loads(fixture)
            certificate = metadata["thumbprint"]
            pin = metadata["pin"]
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
            backend = str(BIN / "guest_backend_fixture.exe")
            profile = {
                "listen": {"address": "127.0.0.1", "port": port},
                "certificate_sha256": pin, "token_file": str(token_path),
                "backends": {
                    "guest": {"path": backend, "target_scope": "guest", "args": ["--metadata", "delayed-trace"]},
                    "machine": {"path": backend, "target_scope": "vm", "args": ["--metadata", "machine"]},
                    "host": {"path": backend, "target_scope": "host", "args": ["--metadata", "host-cap"], "allow_launch": True},
                    **{alias: {"path": backend, "target_scope": "guest", "args": ["--metadata", mode]}
                       for alias, mode in (("early", "early-exit"), ("ready-exit", "ready-exit"),
                                           ("cap-exit", "cap-exit"), ("scope-mismatch", "host-cap"), ("state-refusal", "shellcode-state"),
                                           ("diagnostic-driver", "diagnostic-driver"), ("diagnostic-abi", "diagnostic-abi"),
                                           ("diagnostic-invalid", "diagnostic-invalid"))},
                    "missing-agent": {"path": str(directory / "missing-agent.exe"), "target_scope": "guest"},
                }}
            runner_profile = directory / "runner.json"
            runner_profile.write_text(json.dumps(profile), encoding="utf-8")
            runner = subprocess.Popen(
                [str(BIN / "veh-remote-runner.exe"), "--profile", str(runner_profile)],
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                creationflags=CREATE_NO_WINDOW)
            def read_runner():
                for line in runner.stderr:
                    runner_lines.put(line)
                runner_lines.put(None)
            runner_reader = threading.Thread(target=read_runner, daemon=True)
            runner_reader.start()
            ready = runner_lines.get(timeout=15)
            assert ready and b"listening" in ready, "resident runner startup"

            guest_request = {"backend": "guest", "operation": "attach", "target_scope": "guest", "pid": 424242}
            peer, first = raw_open(port, pin, token, guest_request)
            try:
                raw_threads(peer)
                original_work = first["work_id"]
                assert len(original_work) == 64 and first["outcome_unknown"] is False
            finally:
                peer.close()  # unexpected transport loss; retain backend lease
            # Unbind races socket close; retry only explicit busy replies, never mutating work.
            deadline = time.monotonic() + 5
            second = None
            for reconnect_attempt in range(3):
                if time.monotonic() >= deadline:
                    break
                peer = connect(port, pin)
                try:
                    authenticate(peer, token)
                    control(peer, 4, json.dumps(guest_request).encode())
                    reply = json.loads(read_control(peer, 5))
                    if not reply.get("success"):
                        assert reply.get("code") == "busy", "unexpected reconnect refusal"
                        threading.Event().wait(min(0.05, max(0, deadline - time.monotonic())))
                        continue
                    assert struct.unpack("<II", exact(peer, 8)) == (0x1000, 0)
                    raw_threads(peer)
                    second = reply
                    peer.sendall(struct.pack("<II", 0xF0, 0))
                    break
                finally:
                    peer.close()
            assert second and second["work_id"] == original_work, "retained work identity"
            assert second["outcome_unknown"] is False, "idle reconnect outcome"
            passed("TLS challenge, raw IPC threads and retained reconnect identity")

            peer = connect(port, pin)
            try:
                saved_proof = authenticate(peer, token)
            finally:
                peer.close()
            replay_rejected = False
            peer = connect(port, pin)
            try:
                try:
                    authenticate(peer, token, proof=saved_proof)
                except (EOFError, ssl.SSLError, ConnectionError):
                    replay_rejected = True
            finally:
                peer.close()
            assert replay_rejected, "replayed proof accepted"
            passed("fresh server nonce rejects prior connection proof")

            bad_token = directory / "bad-token.txt"
            bad_token.write_text(secrets.token_hex(32), encoding="ascii")
            # Same restrictive ACL as the valid token, so rejection tests auth itself.
            powershell("$ErrorActionPreference='Stop'; $d=$env:VEH_TEST_TEMP; Set-Acl -LiteralPath (Join-Path $d 'bad-token.txt') -AclObject (Get-Acl -LiteralPath (Join-Path $d 'token.txt'))", directory)
            mappings = {}
            for alias, scope in (("guest", "guest"), ("machine", "vm"), ("host", "host"),
                                 ("early", "guest"), ("ready-exit", "guest"), ("cap-exit", "guest"),
                                 ("diagnostic-driver", "guest"), ("diagnostic-abi", "guest"), ("diagnostic-invalid", "guest"),
                                 ("scope-mismatch", "guest"), ("missing-agent", "guest"), ("state-refusal", "guest")):
                mappings[alias] = {"target_scope": scope, "remote": {
                    "address": "127.0.0.1", "port": port, "certificate_sha256": pin,
                    "token_file": str(token_path), "backend": alias, "timeout_ms": 20000}}
            mappings["badpin"] = json.loads(json.dumps(mappings["guest"]))
            mappings["badpin"]["remote"]["certificate_sha256"] = "0" * 64
            mappings["badauth"] = json.loads(json.dumps(mappings["guest"]))
            mappings["badauth"]["remote"]["token_file"] = str(bad_token)
            table = directory / "backends.json"
            table.write_text(json.dumps(mappings), encoding="utf-8")
            popen = subprocess.Popen
            def hidden_popen(*args, **kwargs):
                kwargs["creationflags"] = kwargs.get("creationflags", 0) | CREATE_NO_WINDOW
                return popen(*args, **kwargs)
            with patch("mcp_test_client.subprocess.Popen", hidden_popen):
                client = McpClient(env=dict(os.environ, VEH_BACKENDS=str(table)))
            clients.append(client)
            client.initialize()
            for alias in ("badpin", "badauth"):
                rejected = client.tool("veh_attach", {"backend": alias, "pid": 424243}, timeout=25)
                assert "error" in rejected, "invalid credentials accepted"
                assert "error" in client.tool("veh_threads"), "failed auth retained session"
            passed("frontend rejects wrong certificate pin and wrong PSK")
            attached = client.tool("veh_attach", {"backend": "guest", "pid": 424244}, timeout=25)
            assert attached.get("success") and attached["addressBits"] == 32, "guest attach"
            assert attached["backend"]["targetScope"] == "guest", "guest scope"
            assert client.tool("veh_threads")["threads"][0]["id"] == 77, "guest threads"
            previous_work = attached["backend"]["remote"]["work_id"]
            for _ in range(20):
                attached = client.tool("veh_attach", {"backend": "guest", "pid": 424244}, timeout=25)
                assert attached.get("success"), attached
                current_work = attached["backend"]["remote"]["work_id"]
                assert current_work != previous_work, "same-PID attach did not complete detach/reconnect"
                previous_work = current_work
            assert client.tool("veh_threads")["count"] == 1
            passed("20 consecutive authenticated same-PID reattachments without sleeps or quota failures")
            assert client.tool("veh_attach", {"backend": "state-refusal", "pid": 424244}, timeout=25).get("success")
            refusal = client.tool("veh_execute_shellcode", {"shellcode": "C3"})
            assert refusal.get("code") == "invalid_state" and refusal.get("backendStatus") == 6, refusal
            batch = client.tool("veh_batch", {"steps": [{"tool": "veh_execute_shellcode", "args": {"shellcode": "C3"}}]})
            assert batch["failed"] == 1 and batch["results"][0]["result"] == refusal, batch
            assert client.tool("veh_attach", {"backend": "guest", "pid": 424244}, timeout=25).get("success")
            passed("target-state refusal survives TCP routing and direct/batch dispatch")
            for alias, exit_code, stages in (
                ("early", 37, ("agent_pipe",)),
                ("ready-exit", 0, ("agent_ready", "agent_pipe")),
                ("cap-exit", 0xC0000135, ("capabilities",)),
            ):
                failure = client.tool("veh_attach", {"backend": alias, "pid": 424244}, timeout=25)
                error = failure.get("error", "")
                assert "agent exited during startup" in error and f"agent_exit_code={exit_code} " in error, failure
                assert f"0x{exit_code:08X}" in error and any(f"stage={stage}" in error for stage in stages), failure
                assert token.hex() not in error and str(directory) not in error and "\n" not in error, "startup diagnostics exposed private text"
                assert client.tool("veh_threads")["count"] == 1, "startup failure replaced current session"
            for alias, kind, detail in (
                ("diagnostic-driver", "backend_unavailable", "driver_open_failed"),
                ("diagnostic-abi", "version_mismatch", "abi_mismatch"),
                ("diagnostic-invalid", None, None),
            ):
                failure = client.tool("veh_attach", {"backend": alias, "pid": 424244}, timeout=25)
                error = failure.get("error", "")
                assert "agent_exit_code=10 " in error and "stage=agent_pipe" in error, failure
                if kind:
                    assert f"error={kind}" in error and f"detail={detail}" in error, failure
                    if alias == "diagnostic-driver":
                        assert "backend_win32_error=5" in error, failure
                else:
                    assert "detail=" not in error and "error=backend_unavailable" not in error, failure
                assert token.hex() not in error and str(directory) not in error, failure
            checks += 1
            missing = client.tool("veh_attach", {"backend": "missing-agent", "pid": 424244}, timeout=25)
            assert "stage=agent_start" in missing.get("error", "") and "win32_error=2" in missing["error"], missing
            assert "agent_exit_code" not in missing["error"], "process that never started reported an exit"
            mismatch = client.tool("veh_attach", {"backend": "scope-mismatch", "pid": 424244}, timeout=25)
            assert "stage=capabilities" in mismatch.get("error", ""), mismatch
            assert "agent_exit_code" not in mismatch["error"], "cleanup termination code was mistaken for startup exit"
            assert client.tool("veh_threads")["count"] == 1
            passed("startup stage, real zero/37/high-bit exit codes and Win32 failure without private text")
            started = time.monotonic()
            trace = client.tool("veh_trace_callers", {"address": "0x1000", "duration_ms": 20000}, timeout=30)
            assert trace.get("totalHits") == 0 and time.monotonic() - started >= 19, "long command disconnected early"
            assert client.tool("veh_threads")["count"] == 1, "long command lost connection"
            passed("20-second command survives idle read deadline without extra authentication")
            for tool_name, arguments, fragment in (
                ("veh_set_breakpoint", {"address": "0x1000", "condition": "RAX == 1"}, "Conditional breakpoint"),
                ("veh_trace_basic_blocks", {"threadId": 77, "code_output": "file"}, "Target-side file"),
                ("veh_trace_basic_blocks", {"threadId": 77, "events_output": "file"}, "Target-side file"),
            ):
                direct = client.tool(tool_name, arguments)
                through_toolbox = client.tool("veh_toolbox", {
                    "operation": "call", "tool": tool_name, "arguments": arguments})
                batch = client.tool("veh_batch", {"steps": [{"tool": tool_name, "args": arguments}]})
                errors = [direct.get("error"), through_toolbox.get("error"),
                          batch["results"][0]["result"].get("error")]
                assert errors[0] and len(set(errors)) == 1 and fragment in errors[0], "remote rejection parity"
                assert batch["failed"] == 1 and batch["succeeded"] == 0, "batch rejection status"
            passed("conditional breakpoint/file trace rejection agrees in direct/toolbox/batch")
            rejected = client.tool("veh_launch", {"backend": "guest", "program": "synthetic.exe"})
            assert "error" in rejected, "guest process launch accepted"
            assert client.tool("veh_threads")["count"] == 1, "launch rejection lost prior guest session"
            detached = client.tool("veh_detach")
            assert detached.get("success") and detached.get("backendCleanupConfirmed") is False, detached
            passed("MCP guest metadata/threads and unsupported launch preserves session")

            batch_marker = directory / "batch-launch.txt"
            batch_release = directory / "batch-launch-release.txt"
            batch_code = ("from pathlib import Path;import time;Path(" + repr(str(batch_marker)) +
                          ").write_text('running');\nwhile not Path(" + repr(str(batch_release)) +
                          ").exists():time.sleep(.02)")
            batch_launch = client.tool("veh_batch", {"steps": [
                {"tool": "veh_launch", "args": {"backend": "host", "program": sys.executable,
                 "args": ["-c", batch_code], "stopOnEntry": False},
                 "result_fields": ["success", "pid", "addressBits", "mainThreadId"]},
                {"tool": "veh_threads", "args": {}, "result_fields": ["count"]},
            ]}, timeout=25)
            batch_started, batch_threads = [item["result"] for item in batch_launch["results"]]
            assert batch_started.get("success") and batch_started.get("pid", 0) > 0, batch_launch
            assert batch_started["addressBits"] == struct.calcsize("P") * 8 and batch_started["mainThreadId"] > 0, batch_launch
            assert batch_threads.get("count") == 1, batch_threads
            batch_target = owned_handle(batch_started["pid"], sys.executable, runner.pid, directory)
            target_handles.append(batch_target)
            wait_file(batch_marker)
            assert client.tool("veh_detach").get("success"), "batch-launched host detach"
            batch_release.write_text("exit", encoding="ascii")
            assert KERNEL.WaitForSingleObject(batch_target, 5000) == 0
            passed("one MCP batch launches through TCP and inspects the remote target")

            machine = client.tool("veh_attach", {"backend": "machine", "target_scope": "vm"}, timeout=25)
            assert machine.get("success") and machine["backend"]["targetScope"] == "vm", "VM attach"
            assert client.tool("veh_detach").get("success"), "VM detach"
            passed("MCP VM scope attach")

            backend_workspace = os.environ.get("VEH_BACKEND_WORKSPACE")
            if backend_workspace:
                workspace = Path(backend_workspace).resolve(strict=True)
                with tempfile.TemporaryDirectory(prefix="tcp-localhost-", dir=workspace / "local") as backend_temp:
                    local = Path(backend_temp)
                    local_table = local / "backends.json"
                    local_table.write_text(json.dumps(mappings), encoding="utf-8")
                    local_profile = local / "profile.json"
                    local_profile.write_text(json.dumps({
                        "mcp_executable": str(BIN / "veh-mcp-server.exe"),
                        "backend_config": str(local_table),
                        "open_arguments": {"backend": "guest", "pid": 424246},
                        "open_expect": {"backend.targetScope": "guest", "addressBits": 32},
                        "checks": [
                            {"tool": "veh_launch", "arguments": {"backend": "guest", "program": "synthetic.exe"}, "expect_error": True},
                            {"tool": "veh_threads", "expect": {"count": 1, "threads.0.id": 77}}],
                        "reconnect_arguments": {"backend": "guest", "pid": 424246},
                        "deadline_seconds": 60}), encoding="utf-8")
                    regression = subprocess.run(
                        [sys.executable, "-B", str(workspace / "tools" / "mcp_remote.py"),
                         "--tcp-profile", str(local_profile)], cwd=workspace,
                        capture_output=True, timeout=90, creationflags=CREATE_NO_WINDOW)
                    assert regression.returncode == 0, "backend protected-profile TCP regression"
                passed("backend mcp_remote protected-profile TCP regression")

            marker = directory / "launched.txt"
            code = "from pathlib import Path;Path(" + repr(str(marker)) + ").write_text('done')"
            failed = client.tool("veh_launch", {"backend": "host", "program": str(directory / "missing-program.exe")}, timeout=25)
            assert "could not be opened" in failed.get("error", ""), "missing program did not return confirmed rejection"
            assert "stage=target_create" in failed["error"] and "win32_error=2" in failed["error"], failed
            # A corrected program must work after a confirmed missing-file
            # rejection. Also lose its first Work reply to exercise genuine
            # uncertainty: a different launch must be refused, and identical
            # retry must recover the exact first PID instead of spawning twice.
            launch_arguments = {
                "backend": "host", "program": sys.executable, "args": ["-c", code], "stopOnEntry": True}
            with DropWorkReplyProxy(port) as proxy:
                mappings["host"]["remote"]["port"] = proxy.port
                table.write_text(json.dumps(mappings), encoding="utf-8")
                lost = client.tool("veh_launch", launch_arguments, timeout=25)
                assert proxy.dropped.is_set() and "result unknown" in lost.get("error", ""), "lost Work reply not uncertain"
                program_info = directory / "launch.json"
                program_info.write_text(json.dumps({"program": sys.executable}), encoding="utf-8")
                first_pid = int(powershell(
                    "$ErrorActionPreference='Stop'; $p=(Get-Content -Raw -LiteralPath (Join-Path $env:VEH_TEST_TEMP 'launch.json')|ConvertFrom-Json).program; "
                    f"Get-CimInstance Win32_Process -Filter \"ParentProcessId={runner.pid}\" | Where-Object {{$_.Name -eq [IO.Path]::GetFileName($p)}} | Select-Object -ExpandProperty ProcessId",
                    directory))
                target = KERNEL.OpenProcess(0x00100000 | 0x1000 | 0x0001, False, first_pid)
                assert target, "owned uncertain launch handle"
                target_handles.append(target)
                image = ctypes.create_unicode_buffer(32768)
                image_size = wintypes.DWORD(len(image))
                assert KERNEL.QueryFullProcessImageNameW(target, 0, image, ctypes.byref(image_size)), "owned target identity query"
                assert Path(image.value).resolve() == Path(sys.executable).resolve(), "owned target path mismatch"
                refused = client.tool("veh_launch", {**launch_arguments, "program": str(directory / "other-program.exe")})
                assert "Previous remote launch may exist" in refused.get("error", ""), "uncertain launch lost protection"
                retry_failed = client.tool("veh_launch", launch_arguments, timeout=25)
                assert proxy.rejected_retry_handshake.is_set() and "authentication failed" in retry_failed.get("error", ""), "retry handshake did not fail"
                refused_again = client.tool("veh_launch", {**launch_arguments, "program": str(directory / "other-program.exe")})
                assert "Previous remote launch may exist" in refused_again.get("error", ""), "failed retry erased earlier uncertainty"
                for _ in range(3):
                    launched = client.tool("veh_launch", launch_arguments, timeout=25)
                    if launched.get("success"):
                        break
                    assert "active connection" in launched.get("error", ""), launched
                    threading.Event().wait(0.05)
                assert launched.get("success") and launched["pid"] == first_pid, "uncertain retry created another target"
                assert launched["addressBits"] == struct.calcsize("P") * 8 and launched["mainThreadId"] > 0, launched
                assert not marker.exists(), "stopOnEntry allowed entry execution"
                assert client.tool("veh_detach").get("success"), "host detach"
                wait_file(marker)
                assert KERNEL.WaitForSingleObject(target, 5000) == 0, "detached owned target did not exit"
            passed("confirmed launch rejection clears state; lost reply retry retains the exact PID")
            passed("host stop-entry launch detach resumes owned primary thread")
            # The earlier replay, wrong pin and wrong PSK were three failures.
            # Valid sessions must neither consume nor erase that failure budget.
            for _ in range(2):
                peer = connect(port, pin)
                rejected = False
                try:
                    try:
                        authenticate(peer, token, proof=b"\0" * 32)
                    except (OSError, EOFError):
                        rejected = True
                finally:
                    peer.close()
                assert rejected, "invalid proof accepted"
            rejected = False
            peer = None
            try:
                peer = connect(port, pin)
                authenticate(peer, token)
            except (OSError, EOFError):
                rejected = True
            finally:
                if peer:
                    peer.close()
            assert rejected, "five failures were erased by successful authentications"
            passed("failed authentication budget persists across successful sessions")
            # Separate resident resets the per-address connection budget for
            # the lifecycle scenarios; every resident here is test-owned.
            runner.terminate()
            runner.wait(timeout=10)
            runner_reader.join(timeout=2)
            runner.stderr.close()
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
            profile["listen"]["port"] = port
            profile["backends"] = {
                alias: {"path": backend, "target_scope": "guest", "args": ["--metadata", mode]}
                for alias, mode in (("silent", "silent-detach"), ("late", "late-detach"))}
            profile["backends"]["host"] = {"path": backend, "target_scope": "host", "args": ["--metadata", "host-cap"], "allow_launch": True}
            runner_profile.write_text(json.dumps(profile), encoding="utf-8")
            runner = subprocess.Popen([str(BIN / "veh-remote-runner.exe"), "--profile", str(runner_profile)],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, creationflags=CREATE_NO_WINDOW)
            runner_lines = queue.Queue()
            runner_reader = threading.Thread(target=read_runner, daemon=True)
            runner_reader.start()
            assert b"listening" in runner_lines.get(timeout=15)
            mappings = {alias: {"target_scope": "host" if alias == "host" else "guest", "remote": {
                "address": "127.0.0.1", "port": port, "certificate_sha256": pin, "token_file": str(token_path),
                "backend": alias, "timeout_ms": 20000}} for alias in ("silent", "late", "host")}
            table.write_text(json.dumps(mappings), encoding="utf-8")
            lifecycle_checks(client, runner, directory, target_handles, port, pin, token)
            passed("missing/late detach replies, rapid reconnect and dead-agent replacement")
            dll_lifecycle_checks(directory, target_handles, clients)
            passed("real VEH DLL preserves delayed-read Detach and Shutdown acknowledgements")
        finally:
            cleanup_failures = []
            for client in clients:
                try:
                    client.close(terminate_target=False)
                    assert client.proc.poll() is not None, "owned MCP process remains"
                except Exception:
                    cleanup_failures.append("MCP cleanup")
            for handle in target_handles:
                try:
                    if KERNEL.WaitForSingleObject(handle, 0) == 258:
                        assert KERNEL.TerminateProcess(handle, 1), "owned target cleanup failed"
                        assert KERNEL.WaitForSingleObject(handle, 5000) == 0, "owned target remains"
                except Exception:
                    cleanup_failures.append("target cleanup")
                finally:
                    KERNEL.CloseHandle(handle)
            if runner is not None:
                try:
                    if runner.poll() is None:
                        runner.terminate()
                        try:
                            runner.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            runner.kill()
                            runner.wait(timeout=5)
                    runner_reader.join(timeout=2)
                    runner.stderr.close()
                    assert runner.poll() is not None, "owned resident remains"
                except Exception:
                    cleanup_failures.append("resident cleanup")
            if certificate is not None:
                # Provider removes this test certificate and its private key only.
                cleanup = "$ErrorActionPreference='Stop'; Remove-Item -LiteralPath ('Cert:\\CurrentUser\\My\\' + '" + certificate + "') -DeleteKey"
                try:
                    powershell(cleanup, directory)
                except Exception:
                    cleanup_failures.append("certificate/private key cleanup")
            if cleanup_failures:
                raise RuntimeError(", ".join(cleanup_failures))
    print(f"PASS {checks} localhost remote transport checks; owned processes/certificate/token cleaned")


if __name__ == "__main__":
    run()
