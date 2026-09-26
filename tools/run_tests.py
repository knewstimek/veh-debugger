"""Run the integration test files in parallel with bounded time and cleanup.

Each test/test_*.py file runs in its own process (pytest when it only defines
test_* functions, otherwise as a script) with a per-file timeout, --jobs files at
a time, longest first. Every process a file starts (debug targets, adapters, MCP
servers) is tracked through its parent chain while the file runs and terminated
afterwards; processes of other files and processes that existed before the run
are never touched. Files marked `# requires: x64` are skipped against an x86
build, and files marked `# slow` are skipped with --quick. Prints a duration
table and exits non-zero when any file failed or timed out.
"""
import argparse
import ctypes
import glob
import json
import os
import re
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from ctypes import wintypes

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TEST_DIR = os.path.join(ROOT, "test")
FAIL_PATTERN = re.compile(r"^\s*(\[?FAIL\]?[: ]|FAILED\b|.*\bTEST FAILED\b)", re.M)


def kill_tree(pid):
    subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True, timeout=30)


def is_x86_build(build_dir):
    release = os.path.join(build_dir, "bin", "Release")
    return (os.path.exists(os.path.join(release, "vcruntime_net32.dll")) and
            not os.path.exists(os.path.join(release, "vcruntime_net.dll")))


def job_pids(job):
    """Live pids currently assigned to the job object (best-effort)."""
    kernel32 = ctypes.windll.kernel32
    # JOBOBJECT_BASIC_PROCESS_ID_LIST with room for up to 1024 pids.
    class _IdList(ctypes.Structure):
        _fields_ = [("NumberOfAssignedProcesses", wintypes.DWORD),
                    ("NumberOfProcessIdsInList", wintypes.DWORD),
                    ("ProcessIdList", ctypes.c_size_t * 1024)]
    info = _IdList()
    if not kernel32.QueryInformationJobObject(job, 3, ctypes.byref(info), ctypes.sizeof(info), None):
        return []
    return [info.ProcessIdList[i] for i in range(min(info.NumberOfProcessIdsInList, 1024))]


def run_file(name, env, timeout, x86, quick):
    source = open(os.path.join(TEST_DIR, name), encoding="utf-8").read()
    if x86 and "# requires: x64" in source:
        return "skip(x64)", 0.0, "", 0
    if quick and re.search(r"^# slow\b", source, re.M):
        return "skip(slow)", 0.0, "", 0
    use_pytest = "def test_" in source and "__main__" not in source
    cmd = [sys.executable, "-m", "pytest", "-q", name] if use_pytest else [sys.executable, name]
    started = time.monotonic()

    # A per-file Job Object captures every descendant the test spawns (the MCP
    # server, adapter, and test targets) with no polling race, and isolates this
    # file from the others running in parallel. Killing the job kills exactly this
    # file's process tree, including targets orphaned when their launcher exits.
    kernel32 = ctypes.windll.kernel32
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    job = kernel32.CreateJobObjectW(None, None)
    proc = subprocess.Popen(cmd, cwd=TEST_DIR, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    assigned = bool(job) and bool(kernel32.AssignProcessToJobObject(job, int(proc._handle)))
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

    # Anything still alive in the job (minus the exited launcher) is a leak.
    if assigned:
        leaked = len([p for p in job_pids(job) if p and p != proc.pid])
        kernel32.TerminateJobObject(job, 1)
    else:
        # Job assignment failed (rare): fall back to killing the launcher's tree.
        kill_tree(proc.pid)
        leaked = 0
    if job:
        kernel32.CloseHandle(job)
    return status, elapsed, text, leaked


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("patterns", nargs="*", help="Test file globs (default: test_*.py)")
    parser.add_argument("--build-dir", help="Build root exported as VEH_TEST_BUILD_DIR (tests that honor it)")
    parser.add_argument("--timeout", type=float, default=180, help="Per-file timeout in seconds")
    parser.add_argument("--log-dir", help="Write each file's full output here")
    parser.add_argument("--jobs", type=int, default=min(8, os.cpu_count() or 4), help="Files run at once")
    parser.add_argument("--quick", action="store_true", help="Skip files marked '# slow'")
    args = parser.parse_args()

    names = sorted({os.path.basename(p) for pattern in (args.patterns or ["test_*.py"])
                    for p in glob.glob(os.path.join(TEST_DIR, pattern))})
    env = dict(os.environ)
    if args.build_dir:
        env["VEH_TEST_BUILD_DIR"] = os.path.abspath(args.build_dir)
    x86 = is_x86_build(env.get("VEH_TEST_BUILD_DIR", os.path.join(ROOT, "build")))
    if args.log_dir:
        os.makedirs(args.log_dir, exist_ok=True)

    # Longest files first so the slowest one does not start last.
    durations = {}
    durations_path = os.path.join(TEST_DIR, ".test_durations.json")
    try:
        durations = json.load(open(durations_path, encoding="utf-8"))
    except (OSError, ValueError):
        pass
    names.sort(key=lambda n: -durations.get(n, 0))

    results = []
    lock = threading.Lock()
    wall_start = time.monotonic()

    def run_one(name):
        status, elapsed, text, leaked = run_file(name, env, args.timeout, x86, args.quick)
        tail = " | ".join(line for line in text.strip().splitlines()[-2:])[:160]
        with lock:
            results.append((name, status, elapsed, leaked))
            print(f"{status:9} {elapsed:6.1f}s  {name:38} {tail}", flush=True)
            if not status.startswith("skip"):
                durations[name] = round(elapsed, 1)
        if args.log_dir:
            with open(os.path.join(args.log_dir, name + ".log"), "w", encoding="utf-8") as log:
                log.write(text)

    with ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        list(pool.map(run_one, names))
    try:
        with open(durations_path, "w", encoding="utf-8") as out:
            json.dump(durations, out, indent=0, sort_keys=True)
    except OSError:
        pass

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
