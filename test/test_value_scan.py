"""Target-side Cheat Engine style value scan session coverage."""
import os
import time
import tempfile
from pathlib import Path

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
            "operation": "first", "async": False, "result_mode": "list", "compare": "exact", "value": current,
            "module": client.module, "max_results": 1000,
        }, timeout=130)
        assert client.scan_address in _addresses(first), first
        assert first["mode"] in ("list", "snapshot") and first["candidates"] >= 1

        _continue(client)
        time.sleep(2.5)
        _pause(client)
        increased = client.tool("veh_value_scan", {
            "operation": "next", "async": False, "result_mode": "list", "compare": "increased", "max_results": 1000,
        }, timeout=130)
        assert client.scan_address in _addresses(increased), increased

        unchanged = client.tool("veh_value_scan", {
            "operation": "next", "async": False, "result_mode": "list", "compare": "unchanged", "max_results": 1000,
        }, timeout=130)
        assert client.scan_address in _addresses(unchanged), unchanged
    finally:
        _continue(client)


def test_unknown_then_increased(client):
    _pause(client)
    try:
        first = client.tool("veh_value_scan", {
            "operation": "first", "async": False, "result_mode": "list", "compare": "unknown", "module": client.module,
            "max_results": 1000,
        }, timeout=130)
        assert first["mode"] == "snapshot" and first["candidates"] > 0, first
        _continue(client)
        time.sleep(2.5)
        _pause(client)
        narrowed = client.tool("veh_value_scan", {
            "operation": "next", "async": False, "result_mode": "list", "compare": "increased", "max_results": 1000,
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
            "operation": "first", "async": False, "result_mode": "list", "compare": "between", "value": current - 1,
            "value2": current + 1, "module": client.module, "max_results": 1000,
        }, timeout=130)
        assert client.scan_address in _addresses(result), result
    finally:
        _continue(client)


def test_results_paging(client):
    first = client.tool("veh_value_scan", {
        "operation": "first", "async": False, "result_mode": "list", "compare": "exact", "value": 0,
        "module": client.module, "max_results": 2,
    }, timeout=130)
    assert first["candidates"] > 2 and len(first["results"]) == 2, first
    second = client.tool("veh_value_scan", {
        "operation": "results", "offset": 2, "max_results": 2,
    })
    assert second["candidates"] == first["candidates"] and len(second["results"]) == 2, second
    assert _addresses(first).isdisjoint(_addresses(second)), (first, second)


def test_reset_and_errors(client):
    missing = client.tool("veh_value_scan", {"operation": "next", "async": False, "result_mode": "list", "compare": "changed"})
    assert "no active value scan" in missing.get("error", ""), missing
    invalid = client.tool("veh_value_scan", {
        "operation": "first", "async": False, "result_mode": "list", "compare": "changed", "module": client.module,
    })
    assert "only valid for next" in invalid.get("error", ""), invalid

    client.tool("veh_value_scan", {
        "operation": "first", "async": False, "result_mode": "list", "compare": "exact", "value": 0, "module": client.module,
    }, timeout=130)
    reset = client.tool("veh_value_scan", {"operation": "reset"})
    assert reset["candidates"] == 0 and reset["mode"] == "none" and reset["results"] == [], reset
    after = client.tool("veh_value_scan", {"operation": "results"})
    assert "no active value scan" in after.get("error", ""), after


def test_batch_uses_same_value_scan_handler(client):
    report = client.tool("veh_batch", {"stop_on_error": True, "steps": [
        {"tool": "veh_value_scan", "args": {
            "operation": "first", "async": False, "result_mode": "list", "compare": "exact", "value": 0,
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
        "operation": "first", "async": False, "result_mode": "list", "compare": "exact", "value": 0, "module": client.module,
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


def _fixture_memory(client, size=4096):
    allocated = client.tool("veh_allocate_memory", {"size": size})
    assert allocated.get("address"), allocated
    return int(allocated["address"], 16)


def _scan_range(address, size=4096, **options):
    return {"operation": "first", "start": hex(address), "end": hex(address + size),
            "compare": "unknown", "storage": "file", **options}


def _completion(client, receipt):
    assert receipt["state"] == "running" and int(receipt["jobId"]) > 0, receipt
    return client.wait_notification("notifications/veh/value_scan",
        lambda p: p.get("jobId") == receipt["jobId"] and
                  p.get("state") in ("completed", "cancelled", "failed"), timeout=20)


def test_disk_summary_push_page_and_undo_baseline(client):
    address = _fixture_memory(client)
    try:
        temp_before=set(Path(tempfile.gettempdir()).glob("vsc*.tmp"))
        first = _completion(client, client.tool("veh_value_scan", _scan_range(address)))
        owned_files=set(Path(tempfile.gettempdir()).glob("vsc*.tmp"))-temp_before
        assert len(owned_files)==1, len(owned_files)
        assert first["state"] == "completed" and first["candidates"] == 1024, first
        assert first["storage"] == "file" and first["retainedDiskBytes"] > 0, first
        assert first["results"] == [] and first["summaryOnly"], first
        page = client.tool("veh_value_scan", {"operation": "results", "offset": 1023})
        assert len(page["results"]) == 1 and int(page["results"][0]["address"], 16) == address+4092, page
        client.tool("veh_write_memory", {"address": hex(address), "data": "01 00 00 00"})
        filtered = client.tool("veh_value_scan", {
            "operation": "next", "compare": "unchanged", "storage": "file", "async": False})
        assert filtered["candidates"] == 1023 and filtered["undoAvailable"] == 1, filtered
        restored = client.tool("veh_value_scan", {"operation": "undo"})
        assert restored["candidates"] == 1024 and restored["generationId"] == first["generationId"], restored
        assert restored["processed"] == restored["total"] == restored["matched"] == 1024, restored
        increased = _completion(client, client.tool("veh_value_scan", {
            "operation": "next", "compare": "increased", "storage": "file"}))
        assert increased["candidates"] == 1 and _addresses(increased) == {address}, increased
        reset = client.tool("veh_value_scan", {"operation": "reset"})
        assert reset["retainedDiskBytes"] == reset["retainedRamBytes"] == 0, reset
        assert not any(path.exists() for path in owned_files), owned_files
    finally:
        client.tool("veh_value_scan", {"operation": "reset"})
        client.tool("veh_free_memory", {"address": hex(address)})


def test_disk_budget_failure_keeps_generation_and_history(client):
    address = _fixture_memory(client, 2*1024*1024)
    try:
        first = client.tool("veh_value_scan", _scan_range(address, **{"async": False}))
        if first.get("state") == "running":
            first = _completion(client, first)
        failed = client.tool("veh_value_scan", _scan_range(
            address, 2*1024*1024, **{"async": False, "disk_budget_mb": 1}))
        assert failed["state"] == "failed" and "budget exceeded" in failed.get("error", ""), failed
        assert failed["generationId"] == first["generationId"] and failed["candidates"] == 1024, failed
        assert failed["retainedDiskBytes"] == first["retainedDiskBytes"], (first, failed)
        stale = client.tool("veh_value_scan", {"operation": "cancel", "job_id": "18446744073709551615"})
        assert "job_id" in stale.get("error", ""), stale
        assert "exact" in client.tool("veh_value_scan", {"operation": "cancel", "job_id": 1}).get("error", "")
    finally:
        client.tool("veh_value_scan", {"operation": "reset"})
        client.tool("veh_free_memory", {"address": hex(address)})


def test_unaligned_disk_next_and_undo_preserve_overlapping_baselines(client):
    address = _fixture_memory(client)
    try:
        first = client.tool("veh_value_scan", _scan_range(
            address, 16, **{"alignment": 1, "async": False}))
        assert first["candidates"] == 13, first
        client.tool("veh_write_memory", {"address": hex(address+3), "data": "01"})
        changed = client.tool("veh_value_scan", {
            "operation": "next", "compare": "changed", "storage": "file", "async": False})
        assert changed["candidates"] == 4 and _addresses(changed) == set(range(address, address+4)), changed
        client.tool("veh_value_scan", {"operation": "undo"})
        again = client.tool("veh_value_scan", {
            "operation": "next", "compare": "changed", "storage": "file", "async": False})
        assert again["results"] == changed["results"] and again["candidates"] == 4, (changed, again)
    finally:
        client.tool("veh_value_scan", {"operation": "reset"})
        client.tool("veh_free_memory", {"address": hex(address)})



def test_batch_v2_generation_and_cancel_paths(client):
    address = _fixture_memory(client)
    try:
        report = client.tool("veh_batch", {"stop_on_error": True, "steps": [
            {"tool": "veh_value_scan", "args": _scan_range(address, **{"async": False})},
            {"tool": "veh_value_scan", "args": {"operation": "next", "compare": "unchanged", "async": False}},
            {"tool": "veh_value_scan", "args": {"operation": "undo"}},
            {"tool": "veh_value_scan", "args": {"operation": "first", "start": hex(address),
                "end": hex(address+4096), "compare": "unknown"}, "as": "$scan"},
            {"tool": "veh_value_scan", "args": {"operation": "cancel", "job_id": "$scan.jobId"}},
            {"tool": "veh_value_scan", "args": {"operation": "status", "job_id": "$scan.jobId"}},
            {"tool": "veh_value_scan", "args": {"operation": "reset"}},
        ]})
        assert report["failed"] == 0 and report["totalSteps"] == 7, report
        assert report["results"][2]["result"]["generationId"] == report["results"][0]["result"]["generationId"], report
        assert report["results"][-1]["result"]["retainedDiskBytes"] == 0, report
    finally:
        client.tool("veh_value_scan", {"operation": "reset"})
        client.tool("veh_free_memory", {"address": hex(address)})


def test_action_v2_disk_undo_and_async_push(client):
    address = _fixture_memory(client)
    work = _resolve_function(client, "WorkFunction")
    sleep_ex = _resolve_function(client, "kernel32!SleepEx")
    outer = client.tool("veh_set_breakpoint", {"address": work, "hitCondition": "1", "action": [
        {"tool": "veh_value_scan", "args": {"operation": "reset"}},
        {"tool": "veh_value_scan", "args": _scan_range(address, **{"async": False})},
        {"tool": "veh_write_memory", "args": {"address": hex(address), "data": "01 00 00 00"}},
        {"tool": "veh_value_scan", "args": {"operation": "next", "compare": "unchanged", "async": False, "storage": "file"}},
        {"tool": "veh_value_scan", "args": {"operation": "undo"}},
        {"tool": "veh_value_scan", "args": {"operation": "results", "max_results": 1}},
        {"tool": "veh_value_scan", "args": {"operation": "status"}},
        {"tool": "veh_value_scan", "args": {"operation": "next", "compare": "increased", "storage": "file"}},
        {"tool": "veh_set_breakpoint", "args": {"address": sleep_ex}},
    ]})
    inner = None
    try:
        assert outer.get("success"), outer
        hit = client.tool("veh_continue", {"wait": True, "timeout": 5}, timeout=10)
        inner = hit.get("breakpointId")
        assert inner and inner != outer["id"], hit
        state = client.tool("veh_value_scan", {"operation": "status"})
        terminal = client.wait_notification("notifications/veh/value_scan",
            lambda p: p.get("jobId") == state["jobId"] and p.get("state") in ("completed", "failed"), timeout=10)
        assert terminal["candidates"] == 1 and _addresses(terminal) == {address}, terminal
        assert "Breakpoint action completed with an error" not in client.stderr_tail()
    finally:
        if inner: client.tool("veh_remove_breakpoint", {"id": inner})
        client.tool("veh_remove_breakpoint", {"id": outer["id"]})
        _continue(client)
        client.tool("veh_value_scan", {"operation": "reset"})
        client.tool("veh_free_memory", {"address": hex(address)})


def test_long_temp_path_fails_without_terminating_target():
    from owned_mcp_client import OwnedMcpClient
    with tempfile.TemporaryDirectory(prefix="veh-scan-path-") as root:
        folder=Path(root)/("t"*max(1,230-len(root)-1))
        folder.mkdir()
        env=dict(os.environ,TEMP=str(folder),TMP=str(folder))
        with OwnedMcpClient(env=env) as owner:
            owner.initialize()
            launched=owner.tool("veh_launch", {"program": TARGET, "stopOnEntry": False})
            assert launched.get("success"), launched
            address=_fixture_memory(owner)
            result=owner.tool("veh_value_scan", _scan_range(address, **{"async": False}))
            assert result["state"]=="failed" and "temporary scan storage failed" in result.get("error",""), result
            assert owner.tool("veh_modules").get("modules")
            assert not list(folder.glob("vsc*.tmp"))
            owner.tool("veh_terminate")


def test_owned_disk_cleanup_on_abrupt_pipe_loss():
    from owned_mcp_client import OwnedMcpClient
    with OwnedMcpClient() as owner:
        owner.initialize()
        launched=owner.tool("veh_launch", {"program": TARGET, "stopOnEntry": False})
        assert launched.get("success"), launched
        address=_fixture_memory(owner)
        before=set(Path(tempfile.gettempdir()).glob("vsc*.tmp"))
        first=owner.tool("veh_value_scan", _scan_range(address, **{"async": False}))
        assert first["retainedDiskBytes"]>0
        owned=set(Path(tempfile.gettempdir()).glob("vsc*.tmp"))-before
        assert len(owned)==1
        # Exact MCP process started by this context; the owned job retains the target.
        owner.proc.terminate()
        owner.proc.wait(timeout=5)
        with McpClient() as recovered:
            recovered.initialize()
            attached=recovered.tool("veh_attach", {"pid": launched["pid"]})
            assert attached.get("success"), attached
            state=recovered.tool("veh_value_scan", {"operation": "status"})
            assert state["state"]=="idle" and state["retainedDiskBytes"]==0, state
            assert not any(path.exists() for path in owned), owned


@pytest.mark.parametrize("ending", ["detach", "terminate"])
def test_owned_disk_cleanup_on_session_end(ending):
    from owned_mcp_client import OwnedMcpClient
    with OwnedMcpClient() as owner:
        owner.initialize()
        launched=owner.tool("veh_launch", {"program": TARGET, "stopOnEntry": False})
        assert launched.get("success"), launched
        address=_fixture_memory(owner)
        before=set(Path(tempfile.gettempdir()).glob("vsc*.tmp"))
        result=owner.tool("veh_value_scan", _scan_range(address, **{"async": False}))
        assert result["retainedDiskBytes"]>0, result
        owned=set(Path(tempfile.gettempdir()).glob("vsc*.tmp"))-before
        assert len(owned)==1
        from owned_mcp_client import KERNEL
        target=KERNEL.OpenProcess(0x00100000, False, launched["pid"])
        assert target
        try:
            ended=owner.tool("veh_"+ending)
            assert ended.get("success"), ended
            if ending=="terminate":
                assert KERNEL.WaitForSingleObject(target,5000)==0, "target exit deadline"
            assert not any(path.exists() for path in owned), owned
        finally:
            KERNEL.CloseHandle(target)


def test_async_cancel_is_job_scoped_and_keeps_committed_state(client):
    address = _fixture_memory(client, 8*1024*1024)
    try:
        old = client.tool("veh_value_scan", _scan_range(address, **{"async": False}))
        receipt = client.tool("veh_value_scan", _scan_range(address, 8*1024*1024))
        cancelled = client.tool("veh_value_scan", {"operation": "cancel", "job_id": receipt["jobId"]})
        assert cancelled["state"] in ("cancelling", "cancelled", "completed"), cancelled
        terminal = _completion(client, receipt)
        assert terminal["state"] in ("cancelled", "completed"), terminal
        if terminal["state"] == "cancelled":
            assert terminal["generationId"] == old["generationId"] and terminal["candidates"] == 1024, terminal
        state = client.tool("veh_value_scan", {"operation": "status", "job_id": receipt["jobId"]})
        assert state["state"] == terminal["state"], (state, terminal)
    finally:
        client.tool("veh_value_scan", {"operation": "reset"})
        client.tool("veh_free_memory", {"address": hex(address)})
