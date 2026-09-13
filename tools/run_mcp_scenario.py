"""Run a bounded JSON MCP scenario against veh-mcp-server."""
import argparse
import json
import os
import sys


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "test"))
from mcp_test_client import McpClient  # noqa: E402


def resolve(value, variables):
    if isinstance(value, str) and value.startswith("$"):
        parts = value[1:].split(".")
        current = variables.get(parts[0], value)
        for part in parts[1:]:
            if isinstance(current, dict) and part in current:
                current = current[part]
            elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
                current = current[int(part)]
            else:
                return value
        return current
    if isinstance(value, dict):
        return {key: resolve(item, variables) for key, item in value.items()}
    if isinstance(value, list):
        return [resolve(item, variables) for item in value]
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", help="JSON scenario containing a calls array")
    parser.add_argument("--server", help="veh-mcp-server.exe path")
    parser.add_argument("--output", help="new JSON result path; stdout when omitted")
    parser.add_argument("--max-report-bytes", type=int, default=16 * 1024 * 1024,
                        help="serialized report limit (default 16 MiB, max 64 MiB)")
    args = parser.parse_args()
    if args.max_report_bytes < 1024 or args.max_report_bytes > 64 * 1024 * 1024:
        raise SystemExit("--max-report-bytes must be 1024-67108864")
    scenario = json.load(open(args.scenario, encoding="utf-8"))
    calls = scenario.get("calls")
    if not isinstance(calls, list) or not calls or len(calls) > 500:
        raise SystemExit("scenario.calls must contain 1-500 entries")

    variables = {}
    results = []
    client = McpClient(args.server)
    try:
        client.initialize("veh-scenario-runner")
        for index, call in enumerate(calls):
            if not isinstance(call, dict):
                raise ValueError(f"call {index} must be an object")
            timeout = min(max(float(call.get("timeout", 20)), 0.1), 300)
            if "tool" in call:
                result = client.tool(call["tool"], resolve(call.get("args", {}), variables), timeout)
            elif "method" in call:
                result = client.call(call["method"], resolve(call.get("params"), variables), timeout)
            else:
                raise ValueError(f"call {index} requires tool or method")
            failed = isinstance(result, dict) and ("error" in result or result.get("success") is False)
            results.append({"index": index, "status": "failed" if failed else "ok", "result": result})
            if "as" in call:
                variables[str(call["as"]).lstrip("$")] = result
            if failed and scenario.get("stop_on_error", True):
                break
        report = {"schema_version": 1, "calls": results,
                  "succeeded": sum(item["status"] == "ok" for item in results),
                  "failed": sum(item["status"] == "failed" for item in results)}
        payload = json.dumps(report, indent=2) + "\n"
        if len(payload.encode("utf-8")) > args.max_report_bytes:
            raise ValueError("scenario report exceeds --max-report-bytes; use trace output_file or reduce the scenario")
        if args.output:
            with open(args.output, "x", encoding="utf-8", newline="\n") as output:
                output.write(payload)
        else:
            print(payload, end="")
    finally:
        client.close(terminate_target=scenario.get("terminate_target", True))


if __name__ == "__main__":
    main()
