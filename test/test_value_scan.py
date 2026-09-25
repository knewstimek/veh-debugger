"""Target-side Cheat Engine style value scan session coverage."""
import os
import time

import pytest

from build_paths import RELEASE
from mcp_test_client import McpClient


TARGET = os.path.join(RELEASE, "test_target.exe")
MARKER = "5A 3C 96 E1 7D 42 B8 0F C6 29 73 AE 14 D5 68 9B"


@pytest.fixture(scope="module")
def client():
    with McpClient() as c:
        c.initialize("value-scan-test")
        launched = c.tool("veh_launch", {"program": TARGET, "stopOnEntry": False})
        assert launched.get("success"), launched
        module = next(m for m in c.tool("veh_modules")["modules"] if "test_target" in m["name"].lower())
        c.module = module["name"]
        marker = c.tool("veh_search_memory", {"pattern": MARKER, "module": c.module}, timeout=130)
        assert marker.get("count") == 1, marker
        # The writable fixtures are adjacent globals in test_target's data section.
        c.scan_address = int(marker["matches"][0]["address"], 16) + 16
        yield c


@pytest.fixture(autouse=True)
def reset_scan(client):
    client.tool("veh_value_scan", {"operation": "reset"})
    yield
    client.tool("veh_value_scan", {"operation": "reset"})


def _read_i32(client, address):
    result = client.tool("veh_read_memory", {"address": hex(address), "size": 4})
    data = bytes.fromhex(result["hex"])
    return int.from_bytes(data, "little", signed=True)


def _pause(client):
    result = client.tool("veh_pause", {"threadId": 0})
    assert result.get("success"), (result, client.stderr_tail())


def _continue(client):
    result = client.tool("veh_continue", {"threadId": 0})
    assert "error" not in result, (result, client.stderr_tail())


def _addresses(result):
    return {int(entry["address"], 16) for entry in result["results"]}


def _resolve_function(client, name):
    result = client.tool("veh_set_function_breakpoint", {"name": name})
    assert result.get("success") and result.get("address"), result
    removed = client.tool("veh_remove_breakpoint", {"id": result["id"]})
    assert removed.get("success"), removed
    return result["address"]


def test_exact_then_increased_and_unchanged(client):
    _pause(client)
    try:
        current = _read_i32(client, client.scan_address)
        first = client.tool("veh_value_scan", {
            "operation": "first", "compare": "exact", "value": current,
            "module": client.module, "max_results": 1000,
        }, timeout=130)
        assert client.scan_address in _addresses(first), first
        assert first["mode"] == "list" and first["candidates"] >= 1

        _continue(client)
        time.sleep(2.5)
        _pause(client)
        increased = client.tool("veh_value_scan", {
            "operation": "next", "compare": "increased", "max_results": 1000,
        }, timeout=130)
        assert client.scan_address in _addresses(increased), increased

        unchanged = client.tool("veh_value_scan", {
            "operation": "next", "compare": "unchanged", "max_results": 1000,
        }, timeout=130)
        assert client.scan_address in _addresses(unchanged), unchanged
    finally:
        _continue(client)


def test_unknown_then_increased(client):
    _pause(client)
    try:
        first = client.tool("veh_value_scan", {
            "operation": "first", "compare": "unknown", "module": client.module,
            "max_results": 1000,
        }, timeout=130)
        assert first["mode"] == "snapshot" and first["candidates"] > 0, first
        _continue(client)
        time.sleep(2.5)
        _pause(client)
        narrowed = client.tool("veh_value_scan", {
            "operation": "next", "compare": "increased", "max_results": 1000,
        }, timeout=130)
        assert client.scan_address in _addresses(narrowed), narrowed
        assert narrowed["candidates"] < first["candidates"], (first, narrowed)
    finally:
        _continue(client)


def test_between(client):
    _pause(client)
    try:
        current = _read_i32(client, client.scan_address)
        result = client.tool("veh_value_scan", {
            "operation": "first", "compare": "between", "value": current - 1,
            "value2": current + 1, "module": client.module, "max_results": 1000,
        }, timeout=130)
        assert client.scan_address in _addresses(result), result
    finally:
        _continue(client)


def test_results_paging(client):
    first = client.tool("veh_value_scan", {
        "operation": "first", "compare": "exact", "value": 0,
        "module": client.module, "max_results": 2,
    }, timeout=130)
    assert first["candidates"] > 2 and len(first["results"]) == 2, first
    second = client.tool("veh_value_scan", {
        "operation": "results", "offset": 2, "max_results": 2,
    })
    assert second["candidates"] == first["candidates"] and len(second["results"]) == 2, second
    assert _addresses(first).isdisjoint(_addresses(second)), (first, second)


def test_reset_and_errors(client):
    missing = client.tool("veh_value_scan", {"operation": "next", "compare": "changed"})
    assert "no active value scan" in missing.get("error", ""), missing
    invalid = client.tool("veh_value_scan", {
        "operation": "first", "compare": "changed", "module": client.module,
    })
    assert "only valid for next" in invalid.get("error", ""), invalid

    client.tool("veh_value_scan", {
        "operation": "first", "compare": "exact", "value": 0, "module": client.module,
    }, timeout=130)
    reset = client.tool("veh_value_scan", {"operation": "reset"})
    assert reset["candidates"] == 0 and reset["mode"] == "none" and reset["results"] == [], reset
    after = client.tool("veh_value_scan", {"operation": "results"})
    assert "no active value scan" in after.get("error", ""), after


def test_batch_uses_same_value_scan_handler(client):
    report = client.tool("veh_batch", {"stop_on_error": True, "steps": [
        {"tool": "veh_value_scan", "args": {
            "operation": "first", "compare": "exact", "value": 0,
            "module": client.module, "max_results": 2,
        }},
        {"tool": "veh_value_scan", "args": {
            "operation": "results", "offset": 1, "max_results": 1,
        }},
    ]}, timeout=130)
    assert report.get("failed") == 0 and report.get("totalSteps") == 2, report
    assert report["results"][1]["result"]["offset"] == 1, report


def test_breakpoint_action_uses_same_value_scan_handler(client):
    client.tool("veh_value_scan", {
        "operation": "first", "compare": "exact", "value": 0, "module": client.module,
    }, timeout=130)
    work = _resolve_function(client, "WorkFunction")
    sleep_ex = _resolve_function(client, "kernel32!SleepEx")
    outer = client.tool("veh_set_breakpoint", {
        "address": work, "hitCondition": "1", "action": [
            {"tool": "veh_value_scan", "args": {"operation": "reset"}},
            {"tool": "veh_set_breakpoint", "args": {"address": sleep_ex}},
        ],
    })
    assert outer.get("success") and outer.get("hasAction"), outer
    try:
        hit = client.tool("veh_continue", {"wait": True, "timeout": 5}, timeout=10)
        assert hit.get("breakpointId") and hit.get("breakpointId") != outer["id"], hit
        missing = client.tool("veh_value_scan", {"operation": "results"})
        assert "no active value scan" in missing.get("error", ""), missing
        client.tool("veh_remove_breakpoint", {"id": hit["breakpointId"]})
    finally:
        client.tool("veh_remove_breakpoint", {"id": outer["id"]})
        _continue(client)
