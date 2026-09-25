"""veh_search_memory / veh_memory_map run inside the target (backend IPC commands).

test_target keeps a unique 16-byte marker in .data (g_search_marker).
"""
import os
import secrets

import pytest

from build_paths import RELEASE
from mcp_test_client import McpClient

TARGET = os.path.join(RELEASE, "test_target.exe")
MARKER = "5A 3C 96 E1 7D 42 B8 0F C6 29 73 AE 14 D5 68 9B"


@pytest.fixture(scope="module")
def client():
    with McpClient() as c:
        c.initialize("memory-search-test")
        assert c.tool("veh_launch", {"program": TARGET, "stopOnEntry": False}).get("success")
        module = next(m for m in c.tool("veh_modules")["modules"] if "test_target" in m["name"].lower())
        c.module = module["name"]
        yield c


def _search(client, **args):
    result = client.tool("veh_search_memory", args, timeout=130)
    assert "error" not in result, result
    return result


def test_aob_finds_marker_in_image(client):
    found = _search(client, pattern=MARKER, module=client.module)
    assert found["count"] == 1, found
    hit = found["matches"][0]
    assert hit["location"].lower().startswith(client.module.lower() + "+"), hit
    data = client.tool("veh_read_memory", {"address": hit["address"], "size": 16})
    assert data["hex"].replace(" ", "").upper() == MARKER.replace(" ", ""), data


def test_wildcards_and_nibbles(client):
    exact = _search(client, pattern=MARKER, module=client.module)["matches"][0]["address"]
    wild = _search(client, pattern="5A 3C ?? E1 7? 42 B8 ?F C6", module=client.module)
    assert [m["address"] for m in wild["matches"]] == [exact], wild
    packed = _search(client, pattern="5A3C96E17D42B80F", module=client.module)
    assert [m["address"] for m in packed["matches"]] == [exact], packed


def test_whole_process_includes_image_hit_and_filters(client):
    everywhere = _search(client, pattern=MARKER, max_results=50)
    assert any(m.get("location", "").lower().startswith(client.module.lower()) for m in everywhere["matches"])
    assert everywhere["regionsScanned"] > 1 and everywhere["scannedBytes"] > 0
    # .data is writable and not executable
    assert _search(client, pattern=MARKER, module=client.module, writable=False)["count"] == 0
    assert _search(client, pattern=MARKER, module=client.module, executable=False)["count"] == 1
    assert _search(client, pattern=MARKER, type="private", module=client.module)["count"] == 0


def test_pattern_from_request_is_not_found(client):
    # A random pattern only exists in the search request itself (and freed copies of it).
    needle = " ".join(f"{b:02X}" for b in secrets.token_bytes(24))
    assert _search(client, pattern=needle)["count"] == 0
    assert _search(client, pattern=needle)["count"] == 0


def test_truncation_resumes(client):
    first = _search(client, pattern="00 00 00 00", module=client.module, max_results=3)
    assert first["truncated"] and first["count"] == 3, first
    nxt = _search(client, pattern="00 00 00 00", module=client.module, max_results=3, start=first["next_start"])
    assert int(nxt["matches"][0]["address"], 16) == int(first["next_start"], 16)
    assert int(nxt["matches"][0]["address"], 16) > int(first["matches"][-1]["address"], 16)


def test_value_and_string_arguments(client):
    assert "error" in client.tool("veh_search_memory", {"pattern": "?? ??"})
    assert "error" in client.tool("veh_search_memory", {"pattern": "00", "value": 1})
    ascii_hit = _search(client, string="VEH Debugger Test Target", type="image", module=client.module)
    assert ascii_hit["count"] >= 1, ascii_hit
    marker = int(_search(client, pattern=MARKER, module=client.module)["matches"][0]["address"], 16)
    # marker bytes 42 B8 0F C6 at +5 read as little-endian u32 0xC60FB842
    value = _search(client, value="0xC60FB842", value_type="u32", module=client.module)
    assert marker + 5 in [int(m["address"], 16) for m in value["matches"]], value
    assert value["patternSize"] == 4


def test_memory_map(client):
    regions = client.tool("veh_memory_map", {"module": client.module})
    assert regions["count"] >= 3 and not regions["truncated"], regions
    protects = {r["protect"] for r in regions["regions"]}
    assert "rx" in protects and "r" in protects, protects
    assert all(r["type"] == "image" for r in regions["regions"])
    assert regions["regions"][0]["module"].lower() == client.module.lower() + "+0x0"

    first = client.tool("veh_memory_map", {"max_regions": 2})
    assert first["truncated"] and first["count"] == 2
    second = client.tool("veh_memory_map", {"max_regions": 2, "start": first["next_start"]})
    assert int(second["regions"][0]["base"], 16) == int(first["next_start"], 16)
