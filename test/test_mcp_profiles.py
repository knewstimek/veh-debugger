"""MCP exposure-profile and lazy toolbox regression tests."""
import json
import os

from mcp_test_client import McpClient, ROOT


def _executable():
    build_dir = os.environ.get("VEH_TEST_BUILD_DIR", os.path.join(ROOT, "build"))
    return os.path.join(build_dir, "bin", "Release", "veh-mcp-server.exe")


def _inventory(profile=None):
    args = [] if profile is None else [f"--profile={profile}"]
    with McpClient(executable=_executable(), args=args) as client:
        initialized = client.initialize("profile-test")["result"]
        tools = client.call("tools/list", {})["result"]["tools"]
        return initialized, tools


def _serialized_size(tools):
    return len(json.dumps(tools, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))


def test_default_lite_profile_is_bounded():
    initialized, tools = _inventory()
    names = {tool["name"] for tool in tools}
    assert names == {
        "veh_toolbox", "veh_attach", "veh_launch", "veh_continue", "veh_batch",
        "veh_terminate", "veh_registers",
    }
    assert _serialized_size(tools) < 8000
    assert len(initialized["instructions"].encode("utf-8")) < 300
    assert all("outputSchema" not in tool for tool in tools)


def test_named_profiles_are_bounded_and_full_remains_available():
    _, interactive = _inventory("interactive")
    _, capture = _inventory("capture")
    _, full = _inventory("full")

    assert len(interactive) <= 10
    assert len(capture) <= 10
    assert len(full) == 53
    assert "veh_trace_basic_blocks" not in {tool["name"] for tool in interactive}
    assert "veh_trace_basic_blocks" in {tool["name"] for tool in capture}
    assert "veh_checkpoint_restore" in {tool["name"] for tool in capture}
    assert _serialized_size(full) > _serialized_size(interactive) * 4


def test_toolbox_describe_handle_and_hidden_call():
    with McpClient(executable=_executable()) as client:
        client.initialize("toolbox-test")
        listed = client.tool("veh_toolbox", {"operation": "list", "query": "checkpoint"})
        names = {tool["name"] for tool in listed["tools"]}
        assert "veh_checkpoint_create" in names
        assert "veh_checkpoint_restore" in names

        described = client.tool("veh_toolbox", {
            "operation": "describe", "tool": "veh_checkpoint_create",
        })
        assert described["inputSchema"]["properties"]["threadId"]["type"] == "integer"
        handle = described["schema_handle"]

        unchanged = client.tool("veh_toolbox", {
            "operation": "describe",
            "tool": "veh_checkpoint_create",
            "schema_handle": handle,
        })
        assert unchanged == {
            "tool": "veh_checkpoint_create",
            "schema_handle": handle,
            "unchanged": True,
        }

        called = client.tool("veh_toolbox", {
            "operation": "call", "tool": "veh_modules", "arguments": {},
        })
        assert called["tool"] == "veh_modules"
        assert "error" in called["result"]
        assert called["error"] == called["result"]["error"]


def test_error_results_set_is_error():
    with McpClient(executable=_executable()) as client:
        client.initialize("is-error-test")
        failed = client.call("tools/call", {
            "name": "veh_toolbox",
            "arguments": {"operation": "call", "tool": "veh_modules", "arguments": {}},
        })["result"]
        assert failed.get("isError") is True
        listed = client.call("tools/call", {
            "name": "veh_toolbox", "arguments": {"operation": "list"},
        })["result"]
        assert "isError" not in listed
