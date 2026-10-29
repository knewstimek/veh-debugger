"""veh_symbolize resolves addresses inside the target (PDB symbol, export, or module+RVA)."""
import os

import pytest

from build_paths import RELEASE
from owned_mcp_client import OwnedMcpClient

TARGET = os.path.join(RELEASE, "test_target.exe")


@pytest.fixture(scope="module")
def session():
    with OwnedMcpClient() as client:
        client.initialize("symbolize-test")
        assert client.tool("veh_launch", {"program": TARGET, "args": ["--symbol-lookup", "--interval", "10"], "stopOnEntry": True}).get("success")
        bp = client.tool("veh_set_function_breakpoint", {"name": "WorkFunction"})
        assert bp.get("success"), bp
        stop = client.tool("veh_continue", {"threadId": 0, "wait": True, "timeout": 30}, timeout=40)
        assert stop.get("stopped"), stop
        client.tool("veh_remove_breakpoint", {"id": bp["id"]})
        modules = {m["name"].lower(): m for m in client.tool("veh_modules")["modules"]}
        yield client, int(stop["address"], 16), modules


def test_pdb_function_and_offset(session):
    client, entry, _ = session
    result = client.tool("veh_symbolize", {"addresses": [hex(entry), hex(entry + 5)]})
    first, second = result["symbols"]
    assert first["function"].endswith("WorkFunction"), first
    assert first["module"].lower() == "test_target.exe", first
    assert first["symbol"] == f"{first['module']}!{first['function']}", first
    assert first["line"] > 0 and first["file"].lower().endswith("main.cpp"), first
    assert second["offset"] == "0x5" and second["symbol"].endswith("+0x5"), second


def test_system_module_and_unmapped_address(session):
    client, _, modules = session
    ntdll = modules["ntdll.dll"]
    inside = int(ntdll["baseAddress"], 16) + 0x1000
    result = client.tool("veh_symbolize", {"addresses": [hex(inside), "0x10"]})
    system, nowhere = result["symbols"]
    assert system["module"].lower() == "ntdll.dll" and system["symbol"], system
    assert nowhere == {"address": "0x10"}, nowhere


def test_module_rva_input_and_batch(session):
    client, entry, modules = session
    base = int(modules["test_target.exe"]["baseAddress"], 16)
    direct = client.tool("veh_symbolize", {"address": f"test_target.exe+{hex(entry - base)}"})
    assert int(direct["symbols"][0]["address"], 16) == entry, direct
    report = client.tool("veh_batch", {"steps": [{"tool": "veh_symbolize", "args": {"address": hex(entry)}}]})
    assert report["results"][0]["result"]["symbols"] == direct["symbols"], report


def test_argument_errors(session):
    client, _, _ = session
    assert "error" in client.tool("veh_symbolize", {})
    assert "error" in client.tool("veh_symbolize", {"address": "not-an-address"})
    assert "error" in client.tool("veh_symbolize", {"addresses": ["0x1000"] * 257})



def test_name_lookup_and_direct_address(session):
    client, entry, _ = session
    result = client.tool("veh_symbolize", {"name": "WorkFunction"})
    assert result.get("resolved") and result["count"] == 1, result
    assert int(result["address"], 16) == entry, result
    listing = client.tool("veh_disassemble", {"address": "test_target.exe!WorkFunction", "count": 1})
    assert int(listing["instructions"][0]["address"], 16) == entry, listing
    report = client.tool("veh_batch", {"steps": [{"tool": "veh_symbolize", "args": {"name": "WorkFunction"}}]})
    assert report["results"][0]["result"] == result, report


def test_real_duplicate_exports_and_limits(session):
    client, _, _ = session
    found = client.tool("veh_symbolize", {"name": "SharedProbe"})
    assert found["count"] == 3 and not found["resolved"] and found["ambiguous"], found
    assert {row["module"].lower() for row in found["matches"]} == {"symbol_lookup_a.dll", "symbol_lookup_b.dll", "symbol_lookup_a_extra.dll"}, found
    rejected = client.tool("veh_disassemble", {"address": "SharedProbe", "count": 1})
    assert rejected.get("code") == "ambiguous_symbol", rejected
    mutation = client.tool("veh_set_breakpoint", {"address": "SharedProbe"})
    assert mutation.get("code") == "ambiguous_symbol", mutation
    limited = client.tool("veh_symbolize", {"name": "SharedProbe", "max_results": 1})
    assert limited["count"] == 1 and limited["truncated"] and not limited["resolved"] and "address" not in limited, limited
    for row in found["matches"]:
        selected = client.tool("veh_symbolize", {"name": row["module"] + "!SharedProbe", "max_results": 1})
        assert selected.get("resolved") and selected["address"] == row["address"], selected
        listing = client.tool("veh_disassemble", {"address": row["module"] + "!SharedProbe", "count": 1})
        assert listing["instructions"][0]["address"] == row["address"], listing
    assert client.tool("veh_symbolize", {"name": "NoSuchSyntheticFunction"})["matches"] == []


def test_prefix_free_hex_and_legacy_numbers(session):
    client, entry, modules = session
    base = int(modules["test_target.exe"]["baseAddress"], 16)
    rva = entry - base
    found = client.tool("veh_symbolize", {"address": f"test_target.exe+{rva:X}"})
    assert int(found["symbols"][0]["address"], 16) == entry, found
    read = client.tool("veh_read_memory", {"address": "test_target.exe+10", "size": 1})
    assert int(read["address"], 16) == base + 0x10, read
    assert "error" in client.tool("veh_read_memory", {"address": "-1", "size": 1})
    assert "error" in client.tool("veh_read_memory", {"address": "0xFFFFFFFFFFFFFFFF+1", "size": 1})
    for args in ({"name": "WorkFunction", "address": hex(entry)}, {"name": "WorkFunction", "max_results": 11},
                 {"name": "WorkFunction", "max_results": 0}, {"name": "WorkFunction", "max_results": "2"}):
        assert "error" in client.tool("veh_symbolize", args), args



def test_synthetic_name_receipts_and_address_rules():
    agent = os.path.join(RELEASE, "guest_backend_fixture.exe")
    with OwnedMcpClient() as client:
        client.initialize("symbol-boundaries")
        def attach(mode):
            result = client.tool("veh_attach", {"pid": 424242, "agent": agent, "target_scope": "guest",
                "agent_args": ["--metadata", mode]})
            assert result.get("success"), result
        def lookup(name="UniqueProbe", **options):
            return client.tool("veh_symbolize", {"name": name, **options})
        attach("symbols-ok")
        many = lookup("ManyProbe*")
        assert many["count"] == 10 and many["truncated"] and not many["resolved"], many
        ambiguous = client.tool("veh_read_memory", {"address": "SharedProbe", "size": 1})
        assert ambiguous.get("code") == "ambiguous_symbol", ambiguous
        batch = client.tool("veh_batch", {"steps": [
            {"tool": "veh_symbolize", "args": {"name": "SharedProbe"}},
            {"tool": "veh_read_memory", "args": {"address": "SharedProbe", "size": 1}},
        ]})
        assert batch["results"][0]["result"]["count"] == 2, batch
        assert batch["results"][1]["result"] == ambiguous, batch
        forwarded = lookup("ForwardedProbe")
        assert not forwarded["resolved"] and forwarded["matches"][0]["address"] is None, forwarded
        assert client.tool("veh_read_memory", {"address": "ForwardedProbe", "size": 1})["code"] == "forwarded_symbol"
        for expression, expected in (("probe_a.dll+10", 0x1010), ("probe_a.dll+352DD", 0x362DD),
                ("UniqueProbe+10", 0x1110), ("UniqueProbe", 0x1100), ("16", 16), ("10AB", 0x10AB)):
            result = client.tool("veh_read_memory", {"address": expression, "size": 1})
            assert int(result["address"], 16) == expected, (expression, result)
        assert "error" in client.tool("veh_read_memory", {"address": "probe_a.dll+FFFFFFFFFFFFFFFF", "size": 1})
        assert "error" in client.tool("veh_read_memory", {"address": "probe_a.dll+100000000", "size": 1})
        assert "error" in client.tool("veh_read_memory", {"address": "Shared*", "size": 1})
        attach("symbols-duplicate-module")
        for tool in ("veh_read_memory", "veh_write_memory", "veh_set_breakpoint"):
            result = client.tool(tool, {"address": "probe_a.dll+10", "data": "90", "size": 1})
            assert result.get("code") == "ambiguous_module", result
        attach("symbols-ok")
        for expression in ("10000110A", "0x10000110A", "4294967296", "0x10000120A-0x100"):
            for tool in ("veh_read_memory", "veh_write_memory", "veh_set_breakpoint"):
                result = client.tool(tool, {"address": expression, "data": "90", "size": 1})
                assert "invalid address" in result.get("error", "").lower(), (expression, tool, result)
        attach("symbols-incomplete")
        assert lookup()["incomplete"] and not lookup()["resolved"]
        assert client.tool("veh_read_memory", {"address": "UniqueProbe", "size": 1})["code"] == "incomplete_symbol_lookup"
        attach("symbols-no-caps")
        assert "0x45" in lookup()["error"]
        # Legacy ResolveFunction is advertised and returns a usable first match.
        # Name-based address admission must still refuse instead of falling back.
        assert client.tool("veh_read_memory", {"address": "SharedProbe", "size": 1})["code"] == "symbol_lookup_failed"
        for mode in ("symbols-error", "symbols-short", "symbols-long", "symbols-count",
                     "symbols-flags", "symbols-name", "symbols-address"):
            attach(mode)
            assert "error" in lookup(), mode



def test_name_search_in_breakpoint_actions():
    import tempfile
    with tempfile.TemporaryDirectory(prefix="veh-symbol-actions-") as directory:
        logfile = os.path.join(directory, "actions.log")
        with OwnedMcpClient(args=["--log=" + logfile]) as client:
            client.initialize()
            attached = client.tool("veh_attach", {"pid": 424242, "agent": os.path.join(RELEASE, "guest_backend_fixture.exe"),
                "target_scope": "guest", "agent_args": ["--metadata", "ops-action-symbols"]})
            assert attached.get("success"), attached
            action = [{"tool": "veh_symbolize", "args": {"name": "SharedProbe"}},
                      {"tool": "veh_symbolize", "args": {"name": "UniqueProbe"}}]
            installed = client.tool("veh_set_breakpoint", {"address": "0x1800", "action": action})
            assert installed.get("success"), installed
            stop = client.tool("veh_continue", {"threadId": 77, "wait": True, "timeout": 3}, timeout=5)
            assert stop.get("breakpointId") == 7, stop
            stats = client.tool("veh_threads")
            assert stats["threads"][0]["name"] == "symbols:2", stats
            assert client.tool("veh_detach").get("success")
        with open(logfile, encoding="utf-8") as handle:
            assert "Breakpoint action completed with an error:" not in handle.read()


def test_windows_export_spelling(session):
    client, _, _ = session
    found = client.tool("veh_symbolize", {"name": "WriteFile"})
    assert found["count"] and all(row["function"] == "WriteFile" for row in found["matches"]), found
    actual = client.tool("veh_symbolize", {"name": "kernelbase.dll!WriteFile"})
    assert actual.get("resolved"), actual
    assert client.tool("veh_symbolize", {"name": "WriteFileW"})["count"] == 0



def test_partial_patch_receipts_survive_address_errors(session):
    client, entry, _ = session
    original = client.tool("veh_read_memory", {"address": hex(entry), "size": 2})["hex"].split()
    patches = [{"address": hex(entry), "data": original[0]},
               {"address": "SharedProbe", "data": "90"},
               {"address": hex(entry + 1), "data": original[1]}]
    direct = client.tool("veh_write_memory", {"patches": patches})
    assert direct.get("succeeded") == 2 and direct.get("failed") == 1, direct
    assert direct["errors"][0]["code"] == "ambiguous_symbol", direct
    batch = client.tool("veh_batch", {"steps": [{"tool": "veh_write_memory", "args": {"patches": patches}}]})
    assert batch["results"][0]["result"] == direct, batch


def test_live_loader_stop_symbol_refresh():
    with OwnedMcpClient() as client:
        client.initialize()
        launched = client.tool("veh_launch", {"program": TARGET, "args": ["--symbol-lookup"], "stopOnEntry": True})
        assert launched.get("success"), launched
        warm = client.tool("veh_symbolize", {"name": "WorkFunction"})
        assert warm.get("resolved"), warm
        assert client.tool("veh_set_function_breakpoint", {"name": "WorkFunction"}).get("success")
        assert client.tool("veh_set_module_breakpoint", {"module": "symbol_lookup_a.dll"}).get("success")
        stopped = client.tool("veh_continue", {"wait": True, "timeout": 5}, timeout=7)
        assert stopped.get("reason") == "module-load", stopped
        symbols = client.tool("veh_symbolize", {"name": "symbol_lookup_a.dll!SharedProbe", "max_results": 1}, timeout=5)
        assert symbols.get("resolved"), symbols
        assert client.tool("veh_set_module_breakpoint", {"clear": True}).get("success")
        stop = client.tool("veh_continue", {"wait": True, "timeout": 5}, timeout=7)
        assert stop.get("reason") == "breakpoint", stop


def test_partial_patch_action_receipt():
    import json
    import tempfile
    with tempfile.TemporaryDirectory(prefix="veh-symbol-patches-") as directory:
        logfile = os.path.join(directory, "actions.log")
        with OwnedMcpClient(args=["--log=" + logfile]) as client:
            client.initialize()
            attached = client.tool("veh_attach", {"pid": 424242, "agent": os.path.join(RELEASE, "guest_backend_fixture.exe"),
                "target_scope": "guest", "agent_args": ["--metadata", "ops-action-symbol-patches"]})
            assert attached.get("success"), attached
            action = [{"tool": "veh_write_memory", "args": {"patches": [
                {"address": "0x2000", "data": "AA"}, {"address": "SharedProbe", "data": "90"},
                {"address": "0x2001", "data": "BB"}]}}]
            assert client.tool("veh_set_breakpoint", {"address": "0x1800", "action": action}).get("success")
            stop = client.tool("veh_continue", {"threadId": 77, "wait": True, "timeout": 3}, timeout=5)
            assert stop.get("breakpointId") == 7, stop
            stats = client.tool("veh_threads")
            assert "writes:2" in stats["threads"][0]["name"], stats
            assert client.tool("veh_detach").get("success")
        with open(logfile, encoding="utf-8") as handle:
            errors = [line.split("Breakpoint action completed with an error: ", 1)[1]
                      for line in handle if "Breakpoint action completed with an error: " in line]
        assert len(errors) == 1, errors
        report = json.loads(errors[0])["results"][0]["result"]
        assert report["succeeded"] == 2 and report["failed"] == 1 and report["errors"][0]["code"] == "ambiguous_symbol", report


def test_native_32bit_numeric_addresses_do_not_wrap(session):
    client, entry, _ = session
    # Query actual executable bitness from its build, not the host interpreter.
    from build_paths import IS_X86
    if not IS_X86:
        return
    high = (entry & ~15) + 0x10000000A
    for expression in (f"{high:X}", hex(high), f"{high + 16:#x}-0x10"):
        result = client.tool("veh_read_memory", {"address": expression, "size": 1})
        assert "invalid address" in result.get("error", "").lower(), result



def test_real_module_unload_and_reload_symbols():
    with OwnedMcpClient() as client:
        client.initialize()
        launched = client.tool("veh_launch", {"program": TARGET, "args": ["--symbol-reload"], "stopOnEntry": True})
        assert launched.get("success"), launched
        marker = client.tool("veh_set_function_breakpoint", {"name": "SymbolReloadMarker"})
        assert marker.get("success"), marker
        previous = None
        for phase in range(4):
            stop = client.tool("veh_continue", {"wait": True, "timeout": 5}, timeout=7)
            assert stop.get("breakpointId") == marker["id"], stop
            found = client.tool("veh_symbolize", {"name": "symbol_lookup_reload.dll!ReloadOnlyProbe", "max_results": 1}, timeout=5)
            if phase % 2 == 0:
                assert found.get("resolved"), found
                previous = found["address"]
            else:
                assert found.get("count") == 0 and not found["resolved"], found
                symbol = client.tool("veh_symbolize", {"address": previous})["symbols"][0]
                assert "ReloadOnlyProbe" not in symbol.get("function", ""), symbol
                assert symbol.get("module", "").lower() != "symbol_lookup_reload.dll", symbol
