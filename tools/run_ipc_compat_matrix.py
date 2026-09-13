"""Stage and run old/new veh_trace_basic_blocks IPC combinations."""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TEST = os.path.join(ROOT, "test", "test_trace_ipc_compat.py")


def release_dir(build):
    path = os.path.join(os.path.abspath(build), "bin", "Release")
    if not os.path.isdir(path):
        raise ValueError(f"missing Release directory: {path}")
    return path


def stage(root, name, mcp_build, dll_build):
    destination = os.path.join(root, name, "bin", "Release")
    os.makedirs(destination)
    shutil.copy2(os.path.join(release_dir(mcp_build), "veh-mcp-server.exe"), destination)
    dll_source = release_dir(dll_build)
    copied = 0
    for dll_name in ("vcruntime_net.dll", "vcruntime_net32.dll"):
        source = os.path.join(dll_source, dll_name)
        if os.path.exists(source):
            shutil.copy2(source, destination)
            copied += 1
    if not copied:
        raise ValueError(f"no injected runtime DLL in {dll_source}")
    return os.path.dirname(os.path.dirname(destination))


def run_case(name, build, target, timeout, expect_file_unsupported=False,
             expect_occurrence_unsupported=False,
             expect_function_scope_unsupported=False,
             expect_target_window_unsupported=False):
    env = os.environ.copy()
    env["VEH_TEST_BUILD_DIR"] = build
    env["VEH_TEST_TARGET"] = os.path.abspath(target)
    if expect_file_unsupported:
        env["VEH_TEST_EXPECT_FILE_UNSUPPORTED"] = "1"
    if expect_occurrence_unsupported:
        env["VEH_TEST_EXPECT_OCCURRENCE_UNSUPPORTED"] = "1"
    if expect_function_scope_unsupported:
        env["VEH_TEST_EXPECT_FUNCTION_SCOPE_UNSUPPORTED"] = "1"
    if expect_target_window_unsupported:
        env["VEH_TEST_EXPECT_TARGET_WINDOW_UNSUPPORTED"] = "1"
    creationflags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
    process = subprocess.Popen([sys.executable, TEST], cwd=ROOT, env=env,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, creationflags=creationflags)
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
        else:
            process.kill()
        stdout, stderr = process.communicate(timeout=15)
        return {"case": name, "status": "timeout", "stderr_tail": stderr[-4000:]}
    return {"case": name, "status": "ok" if process.returncode == 0 else "failed",
            "exit_code": process.returncode,
            "summary": stdout.strip().splitlines()[-1] if stdout.strip() else None,
            "stderr_tail": stderr[-4000:] if process.returncode else ""}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--old-build-dir", required=True)
    parser.add_argument("--new-build-dir", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--expect-old-no-file-mode", action="store_true")
    parser.add_argument("--timeout", type=int, default=90)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="veh-ipc-compat-") as temporary:
        old_mcp_new_dll = stage(temporary, "old-mcp-new-dll", args.old_build_dir, args.new_build_dir)
        new_mcp_old_dll = stage(temporary, "new-mcp-old-dll", args.new_build_dir, args.old_build_dir)
        results = [
            run_case("old-mcp-new-dll", old_mcp_new_dll, args.target, args.timeout),
            run_case("new-mcp-old-dll", new_mcp_old_dll, args.target, args.timeout,
                     args.expect_old_no_file_mode, True, True, True),
        ]
    print(json.dumps({"results": results}, separators=(",", ":")))
    if any(result["status"] != "ok" for result in results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
