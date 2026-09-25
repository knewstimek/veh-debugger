"""Kill only the debug targets this test file launched.

tools/run_tests.py runs test files concurrently, so killing test_target.exe by
image name would take down other files' targets.
"""
import json
import os

LAUNCHED = set()


def note_launch(response):
    """Record the pid from a raw MCP veh_launch response."""
    try:
        data = json.loads(response["result"]["content"][0]["text"])
    except (KeyError, IndexError, TypeError, ValueError):
        return
    if isinstance(data, dict) and data.get("pid"):
        LAUNCHED.add(data["pid"])


def kill_launched():
    for pid in list(LAUNCHED):
        os.system(f"taskkill /PID {pid} /F >nul 2>&1")
    LAUNCHED.clear()
