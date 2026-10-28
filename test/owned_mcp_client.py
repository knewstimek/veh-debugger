"""MCP fixtures with a private Windows job capturing descendants before any request."""
import ctypes
from ctypes import wintypes

from mcp_test_client import McpClient

KERNEL = ctypes.WinDLL("kernel32", use_last_error=True)
KERNEL.CreateJobObjectW.argtypes = (ctypes.c_void_p, wintypes.LPCWSTR)
KERNEL.CreateJobObjectW.restype = wintypes.HANDLE
KERNEL.AssignProcessToJobObject.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
KERNEL.QueryInformationJobObject.argtypes = (wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                            wintypes.DWORD, ctypes.c_void_p)
KERNEL.TerminateJobObject.argtypes = (wintypes.HANDLE, wintypes.UINT)
KERNEL.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
KERNEL.OpenProcess.restype = wintypes.HANDLE
KERNEL.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
KERNEL.CloseHandle.argtypes = (wintypes.HANDLE,)


class OwnedMcpClient(McpClient):
    def __init__(self, **kwargs):
        self.job = None
        super().__init__(**kwargs)
        self.job = KERNEL.CreateJobObjectW(None, None)
        if not self.job or not KERNEL.AssignProcessToJobObject(self.job, int(self.proc._handle)):
            self.close(terminate_target=False)
            raise OSError("Cannot capture the fixture MCP process tree")

    def close(self, terminate_target=False):
        # Job membership records the exact child chain from before initialize,
        # including an agent that failed before exposing its pipe or PID.
        class ProcessList(ctypes.Structure):
            _fields_ = [("assigned", wintypes.DWORD), ("count", wintypes.DWORD),
                        ("ids", ctypes.c_size_t * 128)]
        handles = []
        try:
            # Stop and wait for the spawning MCP before taking the final snapshot.
            super().close(terminate_target=terminate_target)
        finally:
            if self.job:
                try:
                    try:
                        info = ProcessList()
                        assert KERNEL.QueryInformationJobObject(self.job, 3, ctypes.byref(info),
                            ctypes.sizeof(info), None), "fixture job membership"
                        for pid in info.ids[:info.count]:
                            handle = KERNEL.OpenProcess(0x00100000, False, pid)
                            if handle:
                                handles.append(handle)
                    finally:
                        assert KERNEL.TerminateJobObject(self.job, 0), "fixture job cleanup"
                        for handle in handles:
                            assert KERNEL.WaitForSingleObject(handle, 5000) == 0, "fixture exit"
                finally:
                    for handle in handles:
                        KERNEL.CloseHandle(handle)
                    KERNEL.CloseHandle(self.job)
                    self.job = None
