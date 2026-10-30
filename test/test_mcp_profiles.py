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
    # Full inventory grows with new tools; compare both public discovery paths.
    with McpClient(executable=_executable()) as client:
        client.initialize("full-inventory-test")
        listed = client.tool("veh_toolbox", {"operation": "list", "profile": "full"})
        profiles = client.tool("veh_toolbox", {"operation": "profiles"})
    full_names = {tool["name"] for tool in full}
    assert full_names == {tool["name"] for tool in listed["tools"]}
    assert {tool["name"] for tool in interactive + capture} <= full_names
    assert next(p["eager_tools"] for p in profiles["profiles"] if p["name"] == "full") == len(full)
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

        manifest = client.tool("veh_toolbox", {
            "operation": "manifest",
            "tools": ["veh_set_data_breakpoint", "veh_search_memory", "veh_read_memory"],
        })
        assert manifest["count"] == 3
        assert {tool["name"] for tool in manifest["tools"]} == {
            "veh_set_data_breakpoint", "veh_search_memory", "veh_read_memory",
        }
        assert all(tool["schema_handle"].startswith("veh_") for tool in manifest["tools"])
        manifest_unchanged = client.tool("veh_toolbox", {
            "operation": "manifest",
            "tools": ["veh_set_data_breakpoint", "veh_search_memory", "veh_read_memory"],
            "manifest_handle": manifest["manifest_handle"],
        })
        assert manifest_unchanged == {
            "manifest_handle": manifest["manifest_handle"], "count": 3, "unchanged": True,
        }
        full_descriptions = client.tool("veh_toolbox", {
            "operation": "manifest",
            "tools": ["veh_set_data_breakpoint", "veh_search_memory", "veh_read_memory"],
            "compact": False,
            "manifest_handle": manifest["manifest_handle"],
        })
        assert full_descriptions["manifest_handle"] != manifest["manifest_handle"]
        assert "tools" in full_descriptions and full_descriptions.get("unchanged") is None

        called = client.tool("veh_toolbox", {
            "operation": "call", "tool": "veh_modules", "arguments": {},
        })
        assert called["tool"] == "veh_modules"
        assert "error" in called["result"]
        assert called["error"] == called["result"]["error"]


def test_analysis_and_vmguest_share_exact_inventory_and_gateway_schemas():
    expected_analysis = set("""
        veh_attach veh_detach veh_threads veh_modules veh_read_memory veh_registers veh_stack_trace
        veh_set_breakpoint veh_remove_breakpoint veh_continue veh_pause veh_step_in veh_step_over
        veh_step_out veh_toolbox veh_disassemble veh_list_breakpoints veh_execution veh_symbolize
        veh_memory_map veh_exception_info veh_set_data_breakpoint veh_remove_data_breakpoint
        veh_trace_basic_blocks veh_trace_calls veh_trace_callers veh_trace_register veh_trace_memory
        veh_search_memory veh_read_pointer_chain veh_targeted_capture veh_value_scan veh_write_memory
        veh_set_register veh_batch veh_evaluate veh_set_function_breakpoint veh_set_module_breakpoint
        veh_assemble veh_dump_memory veh_resolve_imports
    """.split())
    expected_vm_only = {"veh_processes", "veh_virtual_machine"}
    _, full = _inventory("full")
    full_definitions = {tool["name"]: tool for tool in full}
    for profile, expected in (
        ("analysis", expected_analysis),
        ("vmguest", expected_analysis | expected_vm_only),
    ):
        with McpClient(executable=_executable(), args=[f"--profile={profile}"]) as client:
            client.initialize("analysis-profile-test")
            tools = client.call("tools/list", {})["result"]["tools"]
            names = {tool["name"] for tool in tools}
            assert len(tools) == len(expected) and names == expected
            assert all(tool == full_definitions[tool["name"]] for tool in tools)
            listed = client.tool("veh_toolbox", {"operation": "list", "profile": profile})
            assert {tool["name"] for tool in listed["tools"]} == expected
            manifest = client.tool("veh_toolbox", {"operation": "manifest", "profile": profile})
            assert manifest["count"] == len(expected)
            assert {tool["name"] for tool in manifest["tools"]} == expected
            assert all(tool["inputSchema"] == full_definitions[tool["name"]]["inputSchema"]
                       for tool in manifest["tools"])
            unchanged = client.tool("veh_toolbox", {
                "operation": "manifest", "profile": profile,
                "manifest_handle": manifest["manifest_handle"],
            })
            assert unchanged["unchanged"] and unchanged["count"] == len(expected)
            profiles = client.tool("veh_toolbox", {"operation": "profiles"})
            counts = {item["name"]: item["eager_tools"] for item in profiles["profiles"]}
            assert profiles["active"] == profile
            assert counts["analysis"] == 41 and counts["vmguest"] == 43
            # Visibility never grants backend support; hidden names remain callable.
            direct = client.tool("veh_virtual_machine", {"operation": "status"})
            gateway = client.tool("veh_toolbox", {
                "operation": "call", "tool": "veh_virtual_machine",
                "arguments": {"operation": "status"},
            })
            assert "error" in direct and gateway["result"] == direct


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
