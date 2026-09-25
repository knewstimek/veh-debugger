"""Run the integration test files one by one with bounded time and cleanup.

Each test/test_*.py file runs in its own process (pytest when it only defines
test_* functions, otherwise as a script) with a per-file timeout. Processes that
the file started from inside the repository (debug targets, adapters, MCP
servers) are terminated afterwards, while processes that existed before the file
started are never touched. Files marked `# requires: x64` are skipped against
an x86 build. Prints a duration table and exits non-zero when any file failed
or timed out.
"""
import argparse
import ctypes
import glob
import os
import re
import subprocess
import sys
import time
from ctypes import wintypes

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TEST_DIR = os.path.join(ROOT, "test")
FAIL_PATTERN = re.compile(r"^\s*(\[?FAIL\]?[: ]|FAILED\b|.*\bTEST FAILED\b)", re.M)


class _ProcessEntry(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD), ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD), ("szExeFile", wintypes.WCHAR * 260),
    ]


def repo_processes():
    """Return {pid: exe_path} for running processes whose executable lives inside the repo.

    Uses the Toolhelp snapshot directly; a WMI query costs seconds per call.
    """
    kernel32 = ctypes.windll.kernel32
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.OpenProcess.restype = wintypes.HANDLE
    snapshot = kernel32.CreateToolhelp32Snapshot(0x00000002, 0)  # TH32CS_SNAPPROCESS
    if snapshot == wintypes.HANDLE(-1).value:
        return {}
    pids = []
    entry = _ProcessEntry()
    entry.dwSize = ctypes.sizeof(entry)
    try:
        present = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
        while present:
            pids.append(entry.th32ProcessID)
            present = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snapshot)

    root = os.path.normcase(ROOT)
    found = {}
    buffer = ctypes.create_unicode_buffer(32768)
    for pid in pids:
        handle = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            continue
        try:
            size = wintypes.DWORD(len(buffer))
            if kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
                path = os.path.normcase(os.path.abspath(buffer.value))
                if path.startswith(root):
                    found[pid] = buffer.value
        finally:
            kernel32.CloseHandle(handle)
    return found


def kill_tree(pid):
    subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True, timeout=30)


def is_x86_build(build_dir):
    release = os.path.join(build_dir, "bin", "Release")
    return (os.path.exists(os.path.join(release, "vcruntime_net32.dll")) and
            not os.path.exists(os.path.join(release, "vcruntime_net.dll")))


def run_file(name, env, timeout, x86):
    source = open(os.path.join(TEST_DIR, name), encoding="utf-8").read()
    if x86 and "# requires: x64" in source:
        return "skip(x64)", 0.0, "", 0
    use_pytest = "def test_" in source and "__main__" not in source
    cmd = [sys.executable, "-m", "pytest", "-q", name] if use_pytest else [sys.executable, name]
    before = repo_processes()
    started = time.monotonic()
    proc = subprocess.Popen(cmd, cwd=TEST_DIR, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        output, _ = proc.communicate(timeout=timeout)
        status = "ok" if proc.returncode == 0 else f"fail({proc.returncode})"
    except subprocess.TimeoutExpired:
        kill_tree(proc.pid)
        output, _ = proc.communicate()
        status = "TIMEOUT"
    elapsed = time.monotonic() - started
    text = output.decode(errors="replace")
    if status == "ok" and FAIL_PATTERN.search(text):
        status = "ok*"  # exit 0 but the output reports a failure
    leaked = [pid for pid in repo_processes() if pid not in before]
    for pid in leaked:
        kill_tree(pid)
    return status, elapsed, text, len(leaked)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("patterns", nargs="*", help="Test file globs (default: test_*.py)")
    parser.add_argument("--build-dir", help="Build root exported as VEH_TEST_BUILD_DIR (tests that honor it)")
    parser.add_argument("--timeout", type=float, default=180, help="Per-file timeout in seconds")
    parser.add_argument("--log-dir", help="Write each file's full output here")
    args = parser.parse_args()

    names = sorted({os.path.basename(p) for pattern in (args.patterns or ["test_*.py"])
                    for p in glob.glob(os.path.join(TEST_DIR, pattern))})
    env = dict(os.environ)
    if args.build_dir:
        env["VEH_TEST_BUILD_DIR"] = os.path.abspath(args.build_dir)
    x86 = is_x86_build(env.get("VEH_TEST_BUILD_DIR", os.path.join(ROOT, "build")))
    if args.log_dir:
        os.makedirs(args.log_dir, exist_ok=True)

    results = []
    wall_start = time.monotonic()
    for name in names:
        status, elapsed, text, leaked = run_file(name, env, args.timeout, x86)
        results.append((name, status, elapsed, leaked))
        tail = " | ".join(line for line in text.strip().splitlines()[-2:])[:160]
        print(f"{status:9} {elapsed:6.1f}s  {name:38} {tail}", flush=True)
        if args.log_dir:
            with open(os.path.join(args.log_dir, name + ".log"), "w", encoding="utf-8") as log:
                log.write(text)

    total = sum(r[2] for r in results)
    skipped = [r for r in results if r[1].startswith("skip")]
    bad = [r for r in results if not r[1].startswith(("ok", "skip"))]
    warn = [r for r in results if r[1] == "ok*"]
    leaks = [r for r in results if r[3]]
    wall = time.monotonic() - wall_start
    print(f"\n{len(results)} files ({'x86' if x86 else 'x64'}), {wall:.0f}s wall ({total:.0f}s in tests); "
          f"failed/timeout: {len(bad)}, "
          f"exit-0-with-FAIL: {len(warn)}, skipped: {len(skipped)}, leaked processes cleaned in: {len(leaks)}")
    for name, status, elapsed, leaked in bad + warn:
        print(f"  {status:9} {name}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
