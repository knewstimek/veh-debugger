"""Target-side page protection changes through each supported mechanism."""
import os

import pytest

from build_paths import RELEASE
from mcp_test_client import McpClient


TARGET = os.path.join(RELEASE, "test_target.exe")


@pytest.fixture(scope="module")
def client():
    with McpClient() as c:
        c.initialize("protect-memory-test")
        assert c.tool("veh_launch", {"program": TARGET, "stopOnEntry": False}).get("success")
        yield c


@pytest.fixture
def page(client):
    allocation = client.tool("veh_allocate_memory", {"size": 4096, "protection": "rw"})
    address = allocation["address"]
    try:
        yield address
    finally:
        client.tool("veh_free_memory", {"address": address})


def _protect(client, address, protection, method="api"):
    result = client.tool("veh_protect_memory", {
        "address": address,
        "size": 4096,
        "protection": protection,
        "method": method,
    })
    assert "error" not in result, result
    return result


def _query_page(client, address):
    result = client.tool("veh_memory_map", {
        "start": address,
        "end": hex(int(address, 16) + 4096),
    })
    assert result["count"] == 1, result
    return result["regions"][0]


def test_changes_rw_to_rx_and_memory_map_observes_it(client, page):
    result = _protect(client, page, "rx")
    assert result == {
        "address": page,
        "size": 4096,
        "protection": "rx",
        "old_protection": "rw",
        "method": "api",
    }
    assert _query_page(client, page)["protect"] == "rx"


@pytest.mark.parametrize("method", ["api", "nt", "syscall"])
def test_each_method_reports_the_applied_mechanism(client, page, method):
    result = _protect(client, page, "rx", method)
    assert result["old_protection"] == "rw", result
    if method == "syscall":
        assert result["method"] in {"syscall", "nt"}, result
    else:
        assert result["method"] == method, result


def test_guard_suffix_sets_guard_bit(client, page):
    result = _protect(client, page, "rw+guard")
    assert result["protection"] == "rw+guard", result
    assert result["old_protection"] == "rw", result
    assert _query_page(client, page)["protect"] == "rw+guard"


def test_invalid_protection_and_unmapped_address_fail(client):
    invalid = client.tool("veh_protect_memory", {
        "address": "0x1", "size": 4096, "protection": "invalid",
    })
    assert "error" in invalid, invalid

    unmapped = client.tool("veh_protect_memory", {
        "address": "0x1", "size": 4096, "protection": "rx",
    })
    assert "error" in unmapped and "code" in unmapped, unmapped


def test_batch_can_call_protect_memory(client, page):
    batch = client.tool("veh_batch", {"steps": [{
        "tool": "veh_protect_memory",
        "args": {"address": page, "size": 4096, "protection": "r", "method": "nt"},
    }]})
    result = batch["results"][0]["result"]
    assert result["old_protection"] == "rw", result
    assert result["protection"] == "r", result
    assert result["method"] == "nt", result
