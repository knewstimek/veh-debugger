"""Idle-bounded replacement for subprocess stdout pipes in legacy tests.

A blocking read on a child pipe never returns when the child stops writing, so a
single missing response used to hang a test until an outer runner killed it.
bound(proc) swaps proc.stdout for a reader whose read/readline return b"" after
`idle_timeout` seconds without data, so the callers' own deadline loops get a
chance to run. Callers must retry on b"" until their deadline; `eof` tells a
closed pipe apart from an idle one.
"""
import os
import queue
import threading
import time


class BoundedPipe:
    def __init__(self, stream, idle_timeout=1.0):
        self._stream = stream
        self._chunks = queue.Queue()
        self._buffer = bytearray()
        self._eof = False
        self.idle_timeout = idle_timeout
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self):
        fd = self._stream.fileno()
        try:
            while True:
                chunk = os.read(fd, 65536)
                if not chunk:
                    break
                self._chunks.put(chunk)
        except OSError:
            pass
        finally:
            self._chunks.put(None)

    @property
    def eof(self):
        return self._eof and not self._buffer

    def _fill(self, ready):
        """Pull chunks until ready() or EOF; False when the idle timeout expires first."""
        if self.eof:
            time.sleep(0.05)  # keep callers' retry-until-deadline loops from spinning
            return True
        deadline = time.monotonic() + self.idle_timeout
        while not ready() and not self._eof:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            try:
                chunk = self._chunks.get(timeout=remaining)
            except queue.Empty:
                return False
            if chunk is None:
                self._eof = True
            else:
                self._buffer += chunk
                deadline = time.monotonic() + self.idle_timeout
        return True

    def _take(self, size):
        data = bytes(self._buffer[:size])
        del self._buffer[:size]
        return data

    def read(self, size=-1):
        if size is None or size < 0:
            self._fill(lambda: False)
            return self._take(len(self._buffer))
        if not self._fill(lambda: len(self._buffer) >= size):
            return b""
        return self._take(min(size, len(self._buffer)))

    def readline(self, size=-1):
        if not self._fill(lambda: b"\n" in self._buffer):
            return b""
        end = self._buffer.find(b"\n")
        return self._take(len(self._buffer) if end < 0 else end + 1)

    def __iter__(self):
        while True:
            line = self.readline()
            if not line:
                return
            yield line

    def fileno(self):
        return self._stream.fileno()

    def close(self):
        self._stream.close()


class StderrTail:
    """Drains a child's stderr pipe so a chatty child never blocks on a full pipe.

    Legacy tests open stderr=PIPE but only read it after a crash; read() returns
    the retained tail instead.
    """

    def __init__(self, stream, keep=65536):
        self._stream = stream
        self._keep = keep
        self._data = bytearray()
        self._lock = threading.Lock()
        self._thread = threading.Thread(target=self._pump, daemon=True)
        self._thread.start()

    def _pump(self):
        fd = self._stream.fileno()
        try:
            while True:
                chunk = os.read(fd, 65536)
                if not chunk:
                    return
                with self._lock:
                    self._data += chunk
                    del self._data[:-self._keep]
        except OSError:
            pass

    def read(self, size=-1):
        self._thread.join(timeout=1)
        with self._lock:
            return bytes(self._data)

    def __iter__(self):
        return iter(self.read().splitlines(keepends=True))

    def fileno(self):
        return self._stream.fileno()

    def close(self):
        self._stream.close()


def drain_stderr(proc):
    if proc.stderr is not None and not isinstance(proc.stderr, StderrTail):
        proc.stderr = StderrTail(proc.stderr)
    return proc


def bound(proc, idle_timeout=1.0):
    proc.stdout = BoundedPipe(proc.stdout, idle_timeout)
    return drain_stderr(proc)
