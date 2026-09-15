"""Measure bounded MCP initialize/tools-list metadata for exposure profiles."""
import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "test"))
from mcp_test_client import McpClient  # noqa: E402


def measure(executable, profile):
    with McpClient(executable=executable, args=[f"--profile={profile}"]) as client:
        initialized = client.initialize("schema-meter")["result"]
        tools = client.call("tools/list", {})["result"]["tools"]
    encoded = json.dumps(tools, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return {
        "profile": profile,
        "tool_count": len(tools),
        "tools_list_bytes": len(encoded),
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
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--executable",
        default=str(ROOT / "build" / "bin" / "Release" / "veh-mcp-server.exe"),
    )
    parser.add_argument(
        "--profile", action="append",
        choices=("lite", "interactive", "capture", "full"),
    )
    parser.add_argument("--output")
    args = parser.parse_args()

    profiles = args.profile or ["lite", "interactive", "capture", "full"]
    report = {
        "schema_version": 1,
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
