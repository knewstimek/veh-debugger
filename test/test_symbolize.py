"""veh_symbolize resolves addresses inside the target (PDB symbol, export, or module+RVA)."""
import os

import pytest

from build_paths import RELEASE
from mcp_test_client import McpClient

TARGET = os.path.join(RELEASE, "test_target.exe")


@pytest.fixture(scope="module")
def session():
    with McpClient() as client:
        client.initialize("symbolize-test")
        assert client.tool("veh_launch", {"program": TARGET, "stopOnEntry": True}).get("success")
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
