"""veh_trace_memory collect mode (duration_ms) on the VEH DLL backend: every instruction
writing (or reading/writing) g_counter is counted for a while and nothing stops.

Run from the repository root: py -3 test/test_trace_memory_collect.py
"""
import json
import os
import sys
import time

from build_paths import RELEASE
from mcp_test_client import McpClient

MCP_EXE = os.path.join(RELEASE, "veh-mcp-server.exe")
TARGET = os.path.join(RELEASE, "test_target.exe")


def tool(c, name, args=None, timeout=30):
    return c.tool(name, args or {}, timeout)


def main() -> int:
    c = McpClient(MCP_EXE)
    failures = []
    try:
        c.initialize()
        launched = tool(c, "veh_launch", {"program": TARGET, "args": ["--interval", "20"], "stopOnEntry": False})
        assert launched.get("success"), launched
        # async:false: each scan is done when it answers (docs/VALUE_SCAN.md); `results` pages the candidates
        tool(c, "veh_value_scan", {"operation": "first", "compare": "unknown", "value_type": "i32",
                                   "module": "test_target.exe", "async": False}, timeout=120)
        for _ in range(2):
            time.sleep(0.05)  # the target's loop runs every 20 ms: g_counter has changed
            tool(c, "veh_value_scan", {"operation": "next", "compare": "changed", "value_type": "i32", "async": False},
                 timeout=120)
        narrowed = tool(c, "veh_value_scan", {"operation": "results", "offset": 0, "max_results": 1000})
        tool(c, "veh_value_scan", {"operation": "reset"})
        counter = [e.get("address") for e in narrowed.get("results", narrowed.get("entries", []))][0]
        for access in ("write", "readwrite"):
            r = tool(c, "veh_trace_memory", {"address": counter, "size": 4, "duration_ms": 500, "access": access})
            listed = r.get("instructions", [])
            funcs = {(tool(c, "veh_symbolize", {"address": i["instructionAddress"]}).get("symbols") or [{}])[0]
                     .get("function") for i in listed}
            ok = (r.get("total_hits", 0) >= 5 and listed and all(i.get("addressIs") == "next_instruction" for i in listed)
                  and "main" in funcs)
            print(f"{'ok  ' if ok else 'FAIL'} collect {access}: total={r.get('total_hits')} "
                  f"instructions={len(listed)} funcs={sorted(f for f in funcs if f)}")
            if not ok:
                failures.append(json.dumps(r)[:300])
        alive = tool(c, "veh_threads").get("threads")
        print(f"{'ok  ' if alive else 'FAIL'} target runs on after collecting")
        if not alive:
            failures.append("target gone")
        tool(c, "veh_terminate", {"exitCode": 0})
    finally:
        c.close()
    for f in failures:
        print("  ", f)
    print(f"Results: {2 + 1 - len(failures)} passed, {len(failures)} failed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
