"""Value-scan v2 receipts and old-capability fallback via the existing guest fixture."""
from pathlib import Path
import pytest
from build_paths import RELEASE
from owned_mcp_client import OwnedMcpClient

AGENT = str(Path(RELEASE) / "guest_backend_fixture.exe")

def attach(client, mode):
    result = client.tool("veh_attach", {"pid": 424242, "agent": AGENT,
        "target_scope": "guest", "agent_args": ["--metadata", mode]})
    assert result.get("success"), result

def call(client, args, batch=False):
    if not batch:
        return client.tool("veh_value_scan", args)
    report = client.tool("veh_batch", {"steps": [{"tool": "veh_value_scan", "args": args}]})
    return report["results"][0]["result"]

@pytest.mark.parametrize("batch", [False, True])
def test_exact_id_and_legacy_gate(batch):
    with OwnedMcpClient() as client:
        client.initialize()
        attach(client, "scan-ok")
        result = call(client, {"operation": "status", "job_id": "9007199254740995"}, batch)
        assert result["jobId"] == "9007199254740995" and result["sessionId"] == "9007199254740993", result
        assert result["generationId"] == "9007199254740997" and result["summaryOnly"], result
        attach(client, "scan-legacy")
        for args in ({"operation": "undo"}, {"operation": "status"},
                     {"operation": "first", "compare": "unknown", "storage": "file"}):
            assert call(client, args, batch).get("code") == "unsupported"
        legacy = call(client, {"operation": "first", "compare": "unknown"}, batch)
        assert legacy["candidates"] == 100 and legacy["results"] == [], legacy

@pytest.mark.parametrize("mode", ["notify-error","notify-count"])
def test_malformed_notification_is_not_success(mode):
    with OwnedMcpClient() as client:
        client.initialize()
        attach(client, "scan-"+mode)
        good=call(client, {"operation": "status"})
        assert good["state"]=="completed", good
        with pytest.raises(TimeoutError):
            client.wait_notification("notifications/veh/value_scan",timeout=0.2)

@pytest.mark.parametrize("mode", ["short","version","count","job","progress","state","reserved"])
@pytest.mark.parametrize("batch", [False, True])
def test_bad_receipts(mode, batch):
    with OwnedMcpClient() as client:
        client.initialize()
        attach(client, "scan-"+mode)
        result = call(client, {"operation": "status", "job_id": "9007199254740995"}, batch)
        assert "error" in result, result
