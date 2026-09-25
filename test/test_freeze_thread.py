"""veh_freeze_thread: a frozen thread stays suspended across veh_continue until thawed."""
import os

import pytest

from build_paths import RELEASE
from mcp_test_client import McpClient

TARGET = os.path.join(RELEASE, "test_target.exe")


@pytest.fixture(scope="module")
def session():
    with McpClient() as client:
        client.initialize("freeze-thread-test")
        assert client.tool("veh_launch", {"program": TARGET, "stopOnEntry": True}).get("success")
        bp = client.tool("veh_set_function_breakpoint", {"name": "WorkFunction"})
        assert bp.get("success"), bp
        stop = client.tool("veh_continue", {"threadId": 0, "wait": True, "timeout": 30}, timeout=40)
        assert stop.get("stopped"), stop
        yield client, stop["threadId"]


def _continue(client, seconds):
    return client.tool("veh_continue", {"threadId": 0, "wait": True, "timeout": seconds}, timeout=seconds + 10)


def test_frozen_thread_survives_continue(session):
    client, worker = session
    frozen = client.tool("veh_freeze_thread", {"threadId": worker})
    assert frozen.get("success") and worker in frozen["frozenThreads"], frozen
    listed = {t["id"]: t for t in client.tool("veh_threads")["threads"]}
    assert listed[worker].get("frozen") is True, listed

    # Continue releases the breakpoint stop, but the frozen worker cannot reach WorkFunction again.
    held = _continue(client, 3)
    assert not held.get("stopped"), held
    assert worker in client.tool("veh_freeze_thread", {"threadId": worker})["frozenThreads"]

    thawed = client.tool("veh_freeze_thread", {"threadId": worker, "frozen": False})
    assert thawed.get("success") and thawed["frozenThreads"] == [], thawed
    resumed = _continue(client, 10)
    assert resumed.get("stopped") and resumed["threadId"] == worker, resumed
    assert "frozen" not in {t["id"]: t for t in client.tool("veh_threads")["threads"]}[worker]


def test_thaw_all_and_errors(session):
    client, worker = session
    assert "error" in client.tool("veh_freeze_thread", {"threadId": 0})
    not_frozen = client.tool("veh_freeze_thread", {"threadId": worker, "frozen": False})
    assert "error" in not_frozen and not_frozen["frozenThreads"] == [], not_frozen
    assert client.tool("veh_freeze_thread", {"threadId": worker}).get("success")
    everything = client.tool("veh_freeze_thread", {"threadId": 0, "frozen": False})
    assert everything.get("success") and everything["frozenThreads"] == [], everything
    batch = client.tool("veh_batch", {"steps": [
        {"tool": "veh_freeze_thread", "args": {"threadId": worker}},
        {"tool": "veh_freeze_thread", "args": {"threadId": worker, "frozen": False}},
    ]})
    first, second = (entry["result"] for entry in batch["results"])
    assert first["frozenThreads"] == [worker] and second["frozenThreads"] == [], batch
