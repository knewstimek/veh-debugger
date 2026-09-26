"""Run the direct/batch/breakpoint-action trace parity suite for one or more builds."""
import argparse
import json
import os
import subprocess
import sys


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TEST_RUNNER = os.path.join(ROOT, "tools", "run_tests.py")


def run(build_dir, timeout):
    env = os.environ.copy()
    env["VEH_TEST_BUILD_DIR"] = os.path.abspath(build_dir)
    creationflags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
    process = subprocess.Popen([sys.executable, TEST_RUNNER, "test_trace_basic_blocks.py",
                                "test_trace_memory_access.py", "--jobs", "1",
                                "--timeout", str(timeout)], cwd=ROOT, env=env,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, creationflags=creationflags)
    try:
        stdout, stderr = process.communicate(timeout=2 * timeout + 30)
    except subprocess.TimeoutExpired:
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
        else:
            process.kill()
        stdout, stderr = process.communicate(timeout=15)
        return {"build": os.path.abspath(build_dir), "status": "timeout",
                "stderr_tail": stderr[-4000:]}
    finally:
        # Also clean up this runner and its descendants on interruption.
        if process.poll() is None:
            if os.name == "nt":
                subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
            else:
                process.kill()
            process.wait(timeout=15)
    return {"build": os.path.abspath(build_dir),
            "status": "ok" if process.returncode == 0 else "failed",
            "exit_code": process.returncode,
            "summary": stdout.strip().splitlines()[-1] if stdout.strip() else None,
            "stderr_tail": stderr[-4000:] if process.returncode else ""}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", action="append", required=True,
                        help="Build root; repeat for x64/x86")
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args()
    results = [run(path, args.timeout) for path in args.build_dir]
    print(json.dumps({"results": results}, separators=(",", ":")))
    if any(result["status"] != "ok" for result in results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
