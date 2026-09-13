"""Bounded stdio MCP client shared by integration tests and developer tools."""
from collections import deque
import json
import os
import queue
import subprocess
import threading
import time


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


class McpClient:
    def __init__(self, executable=None, *, cwd=None, env=None, stderr_lines=200):
        build_dir = os.environ.get("VEH_TEST_BUILD_DIR", os.path.join(ROOT, "build"))
        executable = executable or os.path.join(build_dir, "bin", "Release", "veh-mcp-server.exe")
        self.proc = subprocess.Popen(
            [executable], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=cwd, env=env,
        )
        self.seq = 0
        self.responses = queue.Queue()
        self.notifications = deque(maxlen=1000)
        self.stderr = deque(maxlen=stderr_lines)
        self.reader = threading.Thread(target=self._read_responses, daemon=True)
        self.stderr_reader = threading.Thread(target=self._read_stderr, daemon=True)
        self.reader.start()
        self.stderr_reader.start()

    def _read_responses(self):
        try:
            for line in self.proc.stdout:
                try:
                    self.responses.put(json.loads(line))
                except json.JSONDecodeError as error:
                    self.responses.put({"_client_error": f"invalid JSON response: {error}"})
        finally:
            self.responses.put(None)

    def _read_stderr(self):
        for line in self.proc.stderr:
            self.stderr.append(line.decode(errors="replace").rstrip())

    def call(self, method, params=None, timeout=20):
        if self.proc.poll() is not None:
            raise RuntimeError(f"MCP server already exited ({self.proc.returncode}): {self.stderr_tail()}")
        self.seq += 1
        request_id = self.seq
        request = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            request["params"] = params
        self.proc.stdin.write((json.dumps(request, separators=(",", ":")) + "\n").encode())
        self.proc.stdin.flush()
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"{method} timed out after {timeout}s")
            try:
                message = self.responses.get(timeout=remaining)
            except queue.Empty as error:
                raise TimeoutError(f"{method} timed out after {timeout}s") from error
            if message is None:
                raise RuntimeError(f"MCP server exited while waiting for {method}: {self.stderr_tail()}")
            if "_client_error" in message:
                raise RuntimeError(message["_client_error"])
            if message.get("id") == request_id:
                return message
            if "method" in message:
                self.notifications.append(message)

    def initialize(self, name="veh-test-client"):
        return self.call("initialize", {
            "protocolVersion": "2024-11-05",
            "clientInfo": {"name": name, "version": "1"},
            "capabilities": {},
        })

    def tool(self, name, arguments=None, timeout=20):
        response = self.call("tools/call", {"name": name, "arguments": arguments or {}}, timeout)
        if "error" in response:
            raise RuntimeError(response["error"])
        content = response["result"]["content"]
        text = next((item["text"] for item in content if item.get("type") == "text"), None)
        if text is None:
            raise RuntimeError(f"{name} returned no text content")
        return json.loads(text)

    def stderr_tail(self):
        return "\n".join(self.stderr)

    def close(self, terminate_target=True):
        try:
            if terminate_target and self.proc.poll() is None:
                try:
                    self.tool("veh_terminate", timeout=5)
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
            self.reader.join(timeout=1)
            self.stderr_reader.join(timeout=1)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
