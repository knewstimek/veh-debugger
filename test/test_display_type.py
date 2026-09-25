"""veh_display_type reads PDB layouts (and values) inside the target.

test_target defines TypeFixture (base class, bitfields, float, nested struct,
enum, char array, self pointer) and a global instance with known values.
"""
import os

import pytest

from build_paths import RELEASE, IS_X86
from mcp_test_client import McpClient

TARGET = os.path.join(RELEASE, "test_target.exe")
# baseId=42 | flagA=5,flagB=17 -> 0x8D | ratio=1.5f | inner -3,9 | mode 7 | "abc"
INSTANCE_BYTES = "2A 00 00 00 8D 00 00 00 00 00 C0 3F FD FF 09 00 07 00 00 00 61 62 63 00"


@pytest.fixture(scope="module")
def session():
    with McpClient() as client:
        client.initialize("display-type-test")
        assert client.tool("veh_launch", {"program": TARGET, "stopOnEntry": False}).get("success")
        module = next(m["name"] for m in client.tool("veh_modules")["modules"] if "test_target" in m["name"].lower())
        found = client.tool("veh_search_memory", {"pattern": INSTANCE_BYTES, "module": module})
        assert found["count"] == 1, found
        yield client, module, int(found["matches"][0]["address"], 16)


def _members(result):
    assert "error" not in result, result
    return {m["name"]: m for m in result["members"]}


def test_layout(session):
    client, _, _ = session
    result = client.tool("veh_display_type", {"type": "TypeFixture"})
    members = _members(result)
    assert result["size"] == (28 if IS_X86 else 32), result
    assert "<TypeFixtureBase>" in members and members["baseId"]["depth"] == 1, members
    assert members["flagA"]["bits"] == "0:3" and members["flagB"]["bits"] == "3:5", members
    assert members["ratio"]["type"] == "float" and members["ratio"]["offset"] == "0x8", members
    assert members["inner.x"]["offset"] == "0xC" and members["inner.y"]["offset"] == "0xE", members
    assert members["tag"]["type"] == "char[4]" and members["self"]["type"].endswith("*"), members
    assert all("value" not in m for m in members.values())


def test_values_at_address(session):
    client, module, address = session
    members = _members(client.tool("veh_display_type", {"type": f"{module}!TypeFixture", "address": hex(address)}))
    assert members["baseId"]["value"] == 42
    assert members["flagA"]["value"] == 5 and members["flagB"]["value"] == 17
    assert members["ratio"]["value"] == 1.5
    assert members["inner.x"]["value"] == -3 and members["inner.y"]["value"] == 9
    assert members["mode"]["value"] == 7
    assert int(members["self"]["value"], 16) == address


def test_depth_limit_errors_and_batch(session):
    client, _, address = session
    shallow = _members(client.tool("veh_display_type", {"type": "TypeFixture", "depth": 0}))
    assert "inner" in shallow and "inner.x" not in shallow and "baseId" not in shallow, shallow
    assert "error" in client.tool("veh_display_type", {"type": "NoSuchTypeAnywhere"})
    assert "error" in client.tool("veh_display_type", {})
    limited = client.tool("veh_display_type", {"type": "TypeFixture", "max_members": 2})
    assert limited["count"] == 2 and limited["truncated"] is True, limited
    report = client.tool("veh_batch", {"steps": [
        {"tool": "veh_display_type", "args": {"type": "TypeFixture", "address": hex(address)}}]})
    assert _members(report["results"][0]["result"])["mode"]["value"] == 7, report
