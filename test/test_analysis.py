"""Persistent JSON annotations through the production MCP/DLL boundary."""
from contextlib import contextmanager
import ctypes
import hashlib
import json
import os
from pathlib import Path

import pytest

from build_paths import RELEASE
from owned_mcp_client import OwnedMcpClient

BIN = Path(RELEASE)


def environment(root):
    env = {key: value for key, value in os.environ.items() if key not in ("VSCE_PAT", "GH_TOKEN", "GITHUB_TOKEN")}
    env["VEH_ANALYSIS_STATE_DIR"] = str(root / "settings")
    env["VEH_ANALYSIS_DIR"] = ""
    return env


def analysis(client, operation, **kwargs):
    return client.tool("veh_symbolize", {"analysis": {"operation": operation, **kwargs}})


@contextmanager
def native(root, *, project=True, client_args=None):
    with OwnedMcpClient(env=environment(root), args=client_args) as client:
        client.initialize("analysis-test")
        launched = client.tool("veh_launch", {"program": str(BIN / "test_target.exe"), "args": ["--interval", "10"], "stopOnEntry": True})
        assert launched.get("success"), launched
        symbol = client.tool("veh_symbolize", {"name": "WorkFunction"})
        assert symbol.get("resolved"), symbol
        if project:
            opened = analysis(client, "open", directory=str(root / "project"), create=True)
            assert opened.get("success") and opened["remembered"], opened
        yield client, symbol["address"]


def test_persistent_comments_labels_and_restart(tmp_path):
    text = "EAX = 请求长度(bytes), hypothesis; " + "😀" * 70
    with native(tmp_path) as (client, address):
        saved = analysis(client, "set", address=address, label="request_length", comment=text,
            position="after", context="normal request path", evidence=["synthetic-run:input16-output16"])
        assert saved.get("success") and saved["identity"]["persistent_identity"], saved
        record = saved["annotation"]
        digest = hashlib.sha256((BIN / "test_target.exe").read_bytes()).hexdigest()
        assert record["build_id"].startswith("sha256:" + digest + ":"), record
        assert record["revision"] == "1" and record["rva"].startswith("0x"), record
        displayed = client.tool("veh_disassemble", {"address": address, "count": 1})["instructions"][0]
        assert displayed["annotation"]["label"] == "request_length" and not displayed["annotation"]["stale"], displayed
        assert displayed["annotation"]["comment_truncated"], displayed
        assert len(displayed["annotation"]["comment"].encode()) <= 240
        hidden = client.tool("veh_disassemble", {"address": address, "count": 1, "include_annotations": False})
        assert "annotation" not in hidden["instructions"][0], hidden
        symbols = client.tool("veh_symbolize", {"address": address})
        assert symbols["symbols"][0]["annotation"]["code_validation"] == "not_checked", symbols
        batch = client.tool("veh_batch", {"steps": [{"tool": "veh_disassemble", "args": {"address": address, "count": 1}}]})
        assert batch["results"][0]["result"]["instructions"][0] == displayed, batch
        bad = client.tool("veh_batch", {"steps": [{"tool": "veh_symbolize", "args": {"analysis": {"operation": "close"}}}]})
        assert "error" in bad["results"][0]["result"], bad
    with native(tmp_path, project=False) as (client, address):
        assert analysis(client, "status")["enabled"]
        restored = analysis(client, "get", address=address)
        assert restored["annotation"]["id"] == record["id"] and restored["annotation"]["comment"] == text, restored
        assert not restored["stale"], restored
        assert analysis(client, "close")["success"]
    with OwnedMcpClient(env=environment(tmp_path)) as client:
        client.initialize()
        assert not analysis(client, "status")["enabled"]


def test_revision_conflicts_history_search_delete(tmp_path):
    with native(tmp_path) as (first, address), native(tmp_path) as (second, other):
        report = first.tool("veh_batch", {"steps": [{"tool": "veh_symbolize", "args": {"analysis": {
            "operation": "set", "address": address, "comment": "length hypothesis"}}}]})
        one = report["results"][0]["result"]["annotation"]
        updated = analysis(second, "set", address=other, comment="length observed", expected_revision=one["revision"], status="observed")
        assert updated.get("success") and updated["annotation"]["revision"] == "2", updated
        assert updated["annotation"]["history_count"] == 1 and "history" not in updated["annotation"], updated
        historical = analysis(first, "get", id=one["id"], history_limit=1)
        assert historical["annotation"]["history"][0]["comment"] == "length hypothesis", historical
        conflict = analysis(first, "set", address=address, comment="stale writer", expected_revision="1")
        assert conflict["code"] == "analysis_conflict", conflict
        assert analysis(first, "set", address=address, comment="missing revision")["code"] == "analysis_conflict"
        search = analysis(first, "search", query="observed", limit=1)
        assert search["count"] == 1 and search["annotations"][0]["revision"] == "2", search
        offline = analysis(first, "get", id=one["id"])
        assert offline["annotation"]["comment"] == "length observed", offline
        assert analysis(first, "delete", id=one["id"], expected_revision="1")["code"] == "analysis_conflict"
        assert analysis(first, "delete", id=one["id"], expected_revision="2")["success"]
        assert analysis(second, "list")["count"] == 0
    doc = json.loads((tmp_path / "project/analysis.json").read_text(encoding="utf-8"))
    assert doc["entries"] == {} and doc["revision"] == "3", doc


def test_modified_code_is_stale_and_requires_acceptance(tmp_path):
    with native(tmp_path) as (client, address):
        saved = analysis(client, "set", address=address, comment="original instruction")["annotation"]
        original = saved["original_bytes"]
        try:
            changed = client.tool("veh_write_memory", {"address": address, "data": "90"})
            assert "error" not in changed, changed
            row = client.tool("veh_disassemble", {"address": address, "count": 1})["instructions"][0]
            assert row["annotation"]["stale"], row
            refused = analysis(client, "set", address=address, comment="changed", expected_revision="1")
            assert refused["code"] == "analysis_code_changed", refused
            accepted = analysis(client, "set", address=address, comment="changed", expected_revision="1", accept_code_change=True)
            assert accepted["success"] and accepted["annotation"]["original_bytes"] == "90", accepted
        finally:
            restored = client.tool("veh_write_memory", {"address": address, "data": original})
            assert "error" not in restored, restored


def test_unknown_backend_identity_is_session_only(tmp_path):
    records = []
    for run in range(2):
        with OwnedMcpClient(env=environment(tmp_path)) as client:
            client.initialize()
            result = client.tool("veh_attach", {"pid": 424242, "agent": str(BIN / "guest_backend_fixture.exe"),
                "target_scope": "guest", "agent_args": ["--metadata", "symbols-ok"]})
            assert result.get("success"), result
            assert analysis(client, "open", directory=str(tmp_path / "project"), create=True)["success"]
            if run:
                current = analysis(client, "get", address="0x1100")
                assert current["annotation"] is None and not current["identity"]["persistent_identity"], current
            saved = analysis(client, "set", address="0x1100", comment="session-specific code")
            assert saved["success"] and not saved["identity"]["persistent_identity"], saved
            records.append(saved["annotation"]["id"])
    assert records[0] != records[1]


@pytest.mark.parametrize("contents", ["{broken", '{"format":"veh-analysis","version":99}', "[1,2]", '{"nested":' + '[' * 30 + '0' + ']' * 30 + "}"])
def test_corrupt_or_unknown_documents_are_preserved(tmp_path, contents):
    project = tmp_path / "project"
    project.mkdir()
    manifest = project / "analysis.json"
    manifest.write_text(contents, encoding="utf-8")
    with OwnedMcpClient(env=environment(tmp_path)) as client:
        client.initialize()
        result = analysis(client, "open", directory=str(project), create=True)
        assert "error" in result, result
        assert manifest.read_text(encoding="utf-8") == contents
        assert not analysis(client, "status")["enabled"]


def test_invalid_inputs_and_exclusive_writer_lock(tmp_path):
    with native(tmp_path) as (client, address):
        for kwargs in ({"comment": "x" * 4097}, {"comment": "valid", "status": "proven"},
                       {"comment": "valid", "position": "during"}, {"comment": "valid", "evidence": [1]}):
            assert "error" in analysis(client, "set", address=address, **kwargs), kwargs
        assert "error" in analysis(client, "open", directory="relative", create=True)
        assert "error" in analysis(client, "list", limit=101)
        assert "error" in analysis(client, "list", offset=-1)
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateFileW.restype = ctypes.c_void_p
        kernel.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
                                      ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
        kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        handle = kernel.CreateFileW(str(tmp_path / "project/analysis.lock"), 0x80000000, 0, None, 3, 0, None)
        assert handle not in (None, ctypes.c_void_p(-1).value)
        try:
            result = analysis(client, "set", address=address, comment="must not write")
            assert result["code"] == "analysis_busy", result
        finally:
            kernel.CloseHandle(handle)
        assert analysis(client, "list")["count"] == 0
        assert not list((tmp_path / "project").glob(".analysis-*.tmp"))


def test_aslr_rebinding_and_changed_build_isolation(tmp_path):
    original_id = None
    for mode, base in (("symbols-analysis-v1", 0x1000), ("symbols-analysis-moved", 0x4000), ("symbols-analysis-v2", 0x1000)):
        with OwnedMcpClient(env=environment(tmp_path)) as client:
            client.initialize()
            attached = client.tool("veh_attach", {"pid": 424242, "agent": str(BIN / "guest_backend_fixture.exe"),
                "target_scope": "guest", "agent_args": ["--metadata", mode]})
            assert attached.get("success"), attached
            assert analysis(client, "open", directory=str(tmp_path / "project"), create=True)["success"]
            address = hex(base + 0x100)
            if original_id is None:
                saved = analysis(client, "set", address=address, comment="build one", label="length_check")
                assert saved.get("success") and saved["identity"]["persistent_identity"], saved
                original_id = saved["annotation"]["id"]
            elif mode.endswith("moved"):
                found = analysis(client, "get", address=address)
                assert found["annotation"]["id"] == original_id and not found["stale"], found
            else:
                found = analysis(client, "get", address=address)
                assert found["annotation"] is None and found["previous_build_records"] == 1, found
                displayed = client.tool("veh_disassemble", {"address": hex(base + 0x120), "count": 1})["instructions"][0]
                assert "annotation" not in displayed and displayed["analysis_previous_records"] == 1, displayed
                assert analysis(client, "get", id=original_id)["annotation"]["comment"] == "build one"


def test_annotation_mutation_in_breakpoint_action(tmp_path):
    logfile = tmp_path / "actions.log"
    with OwnedMcpClient(env=environment(tmp_path), args=["--log=" + str(logfile)]) as client:
        client.initialize()
        attached = client.tool("veh_attach", {"pid": 424242, "agent": str(BIN / "guest_backend_fixture.exe"),
            "target_scope": "guest", "agent_args": ["--metadata", "ops-action-symbols"]})
        assert attached.get("success"), attached
        assert analysis(client, "open", directory=str(tmp_path / "project"), create=True)["success"]
        action = [{"tool": "veh_symbolize", "args": {"analysis": {
            "operation": "set", "address": "0x1100", "comment": "observed by action", "author": "test-action"}}}]
        installed = client.tool("veh_set_breakpoint", {"address": "0x1800", "action": action})
        assert installed.get("success"), installed
        stop = client.tool("veh_continue", {"threadId": 77, "wait": True, "timeout": 3}, timeout=5)
        assert stop.get("breakpointId") == 7, stop
        # A subsequent request drains completed queued actions before inspecting the store.
        stored = analysis(client, "list")["annotations"]
        assert len(stored) == 1, stored
        found = analysis(client, "get", id=stored[0]["id"])
        assert found["annotation"]["comment"] == "observed by action", found
    assert "Breakpoint action completed with an error:" not in logfile.read_text(encoding="utf-8")


def test_failed_replacement_preserves_original_document(tmp_path):
    with native(tmp_path) as (client, address):
        first = analysis(client, "set", address=address, comment="keep me")["annotation"]
        manifest = tmp_path / "project/analysis.json"
        original = manifest.read_bytes()
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GetFileAttributesW.argtypes = [ctypes.c_wchar_p]
        kernel.GetFileAttributesW.restype = ctypes.c_uint32
        kernel.SetFileAttributesW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32]
        attributes = kernel.GetFileAttributesW(str(manifest))
        assert kernel.SetFileAttributesW(str(manifest), attributes | 1)
        try:
            failed = analysis(client, "set", address=address, comment="do not commit", expected_revision=first["revision"])
            assert failed["code"] == "analysis_write", failed
            assert manifest.read_bytes() == original
        finally:
            assert kernel.SetFileAttributesW(str(manifest), attributes)
        assert not list(manifest.parent.glob(".analysis-*.tmp"))


def test_deleted_then_recreated_annotation_rejects_old_revision(tmp_path):
    with native(tmp_path) as (client, address):
        old = analysis(client, "set", address=address, comment="old")["annotation"]
        assert analysis(client, "delete", id=old["id"], expected_revision=old["revision"])["success"]
        new = analysis(client, "set", address=address, comment="replacement")["annotation"]
        assert new["id"] == old["id"] and new["revision"] != old["revision"], new
        assert analysis(client, "delete", id=old["id"], expected_revision=old["revision"])["code"] == "analysis_conflict"
        assert analysis(client, "set", address=address, comment="stale", expected_revision=old["revision"])["code"] == "analysis_conflict"
        assert analysis(client, "get", address=address)["annotation"]["comment"] == "replacement"


@pytest.mark.parametrize("field", ["author", "status", "position", "context", "history"])
def test_edited_json_cannot_expand_previews(tmp_path, field):
    with native(tmp_path) as (client, address):
        result = analysis(client, "set", address=address, comment="bounded")["annotation"]
        path = tmp_path / "project/analysis.json"
        doc = json.loads(path.read_text(encoding="utf-8"))
        entry = doc["entries"][result["id"]]
        entry[field] = [{"unknown": "x" * 1000000}] if field == "history" else "x" * 1000000
        path.write_text(json.dumps(doc), encoding="utf-8")
        listing = analysis(client, "list", limit=1)
        assert "error" in listing and len(json.dumps(listing)) < 1024, listing
        display = client.tool("veh_disassemble", {"address": address, "count": 1})
        assert "analysis_warning" in display["instructions"][0] and len(json.dumps(display)) < 2048, display


def test_loader_stop_allows_cold_identity_and_note_operations(tmp_path):
    with OwnedMcpClient(env=environment(tmp_path)) as client:
        client.initialize()
        assert client.tool("veh_launch", {"program": str(BIN / "test_target.exe"), "args": ["--symbol-lookup"], "stopOnEntry": True})["success"]
        assert analysis(client, "open", directory=str(tmp_path / "project"), create=True)["success"]
        assert client.tool("veh_set_function_breakpoint", {"name": "WorkFunction"})["success"]
        assert client.tool("veh_set_module_breakpoint", {"module": "symbol_lookup_a.dll"})["success"]
        stopped = client.tool("veh_continue", {"wait": True, "timeout": 5}, timeout=7)
        assert stopped.get("reason") == "module-load", stopped
        symbol = client.tool("veh_symbolize", {"name": "symbol_lookup_a.dll!SharedProbe"})
        saved = analysis(client, "set", address=symbol["address"], comment="loader-held module entry")
        assert saved.get("success") and saved["identity"]["persistent_identity"], saved
        display = client.tool("veh_disassemble", {"address": symbol["address"], "count": 1}, timeout=3)
        assert display["instructions"][0]["annotation"]["comment"] == "loader-held module entry", display
        assert client.tool("veh_set_module_breakpoint", {"clear": True})["success"]
        resumed = client.tool("veh_continue", {"wait": True, "timeout": 5}, timeout=7)
        assert resumed.get("reason") == "breakpoint", resumed


def test_unbound_notes_never_rebind_even_in_same_session(tmp_path):
    with OwnedMcpClient(env=environment(tmp_path)) as client:
        client.initialize()
        assert client.tool("veh_attach", {"pid": 424242, "agent": str(BIN / "guest_backend_fixture.exe"),
            "target_scope": "guest", "agent_args": ["--metadata", "symbols-ok"]})["success"]
        assert analysis(client, "open", directory=str(tmp_path / "project"), create=True)["success"]
        first = analysis(client, "set", address="0x1100", comment="unbound")
        assert not first["identity"]["persistent_identity"], first
        assert analysis(client, "get", address="0x1100")["annotation"] is None
        display = client.tool("veh_disassemble", {"address": "0x1100", "count": 1})["instructions"][0]
        assert "annotation" not in display and display["analysis_unbound_records"] == 1, display
        changed = analysis(client, "set", id=first["annotation"]["id"], expected_revision=first["annotation"]["revision"], comment="edited explicitly")
        assert changed["success"] and changed["code_validation"] == "not_checked", changed
        assert analysis(client, "get", id=first["annotation"]["id"])["annotation"]["comment"] == "edited explicitly"


def test_module_replacement_between_ipc_requests_is_refused(tmp_path):
    for mode in ("symbols-analysis-v1", "symbols-analysis-race-set", "symbols-analysis-race-preview"):
        with OwnedMcpClient(env=environment(tmp_path)) as client:
            client.initialize()
            assert client.tool("veh_attach", {"pid": 424242, "agent": str(BIN / "guest_backend_fixture.exe"),
                "target_scope": "guest", "agent_args": ["--metadata", mode]})["success"]
            assert analysis(client, "open", directory=str(tmp_path / "project"), create=True)["success"]
            if mode.endswith("v1"):
                assert analysis(client, "set", address="0x1100", comment="build A")["success"]
            elif mode.endswith("set"):
                before = (tmp_path / "project/analysis.json").read_bytes()
                failed = analysis(client, "set", address="0x1100", comment="must not bind A metadata to B code", expected_revision="1")
                assert failed["code"] == "analysis_target_changed", failed
                assert before == (tmp_path / "project/analysis.json").read_bytes()
            else:
                output = client.tool("veh_disassemble", {"address": "0x1100", "count": 1})["instructions"][0]
                assert "annotation" not in output and "changed" in output.get("analysis_warning", ""), output


def test_unavailable_module_tracking_does_not_claim_stable_identity(tmp_path):
    with OwnedMcpClient(env=environment(tmp_path)) as client:
        client.initialize()
        assert client.tool("veh_attach", {"pid": 424242, "agent": str(BIN / "guest_backend_fixture.exe"),
            "target_scope": "guest", "agent_args": ["--metadata", "symbols-analysis-unavailable"]})["success"]
        assert analysis(client, "open", directory=str(tmp_path / "project"), create=True)["success"]
        saved = analysis(client, "set", address="0x1100", comment="explicitly unbound")
        assert saved["success"] and not saved["identity"]["persistent_identity"], saved
        display = client.tool("veh_disassemble", {"address": "0x1100", "count": 1})["instructions"][0]
        assert "annotation" not in display and "analysis_warning" in display, display
