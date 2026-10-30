"""Measure bounded MCP initialize/tools-list metadata for exposure profiles."""
import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "test"))
from mcp_test_client import McpClient  # noqa: E402


WORKFLOW_TOOLS = (
    "veh_pause", "veh_set_data_breakpoint", "veh_search_memory", "veh_read_memory",
)


def _encoded_size(value):
    return len(json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))


def measure(executable, profile):
    with McpClient(executable=executable, args=[f"--profile={profile}"]) as client:
        initialized = client.initialize("schema-meter")["result"]
        tools = client.call("tools/list", {})["result"]["tools"]
        describes = [client.tool("veh_toolbox", {
            "operation": "describe", "tool": name,
        }) for name in WORKFLOW_TOOLS]
        manifest = client.tool("veh_toolbox", {
            "operation": "manifest", "tools": list(WORKFLOW_TOOLS),
        })
        unchanged = client.tool("veh_toolbox", {
            "operation": "manifest", "tools": list(WORKFLOW_TOOLS),
            "manifest_handle": manifest["manifest_handle"],
        })
    return {
        "profile": profile,
        "tool_count": len(tools),
        "tools_list_bytes": _encoded_size(tools),
        "input_schema_bytes": sum(
            len(json.dumps(tool.get("inputSchema", {}), separators=(",", ":"),
                           ensure_ascii=False).encode("utf-8"))
            for tool in tools
        ),
        "output_schema_count": sum("outputSchema" in tool for tool in tools),
        "initialize_instructions_bytes": len(
            initialized.get("instructions", "").encode("utf-8")
        ),
        "tool_names": [tool["name"] for tool in tools],
        "workflow_discovery": {
            "tool_names": list(WORKFLOW_TOOLS),
            "individual_describe_calls": len(describes),
            "individual_describe_bytes": sum(_encoded_size(value) for value in describes),
            "manifest_calls": 1,
            "manifest_bytes": _encoded_size(manifest),
            "unchanged_manifest_bytes": _encoded_size(unchanged),
        },
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--executable",
        default=str(ROOT / "build" / "bin" / "Release" / "veh-mcp-server.exe"),
    )
    parser.add_argument(
        "--profile", action="append",
        choices=("lite", "interactive", "capture", "analysis", "vmguest", "full"),
    )
    parser.add_argument("--output")
    args = parser.parse_args()

    profiles = args.profile or ["lite", "interactive", "capture", "analysis", "vmguest", "full"]
    report = {
        "schema_version": 2,
        "executable": os.path.abspath(args.executable),
        "profiles": [measure(args.executable, profile) for profile in profiles],
    }
    text = json.dumps(report, indent=2, ensure_ascii=False)
    if args.output:
        output = Path(args.output)
        if output.exists():
            raise SystemExit(f"refusing to overwrite: {output}")
        output.write_text(text + "\n", encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
