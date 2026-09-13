"""Validate exported veh_trace_basic_blocks JSON/JSONL and optional .vtc code artifact."""
import argparse
import hashlib
import json
import os
import struct


def load_trace(path):
    with open(path, encoding="utf-8") as source:
        first = source.readline()
        if not first:
            raise ValueError("trace file is empty")
        try:
            first_value = json.loads(first)
        except json.JSONDecodeError:
            source.seek(0)
            return json.load(source)
        if first_value.get("record") != "manifest":
            source.seek(0)
            return json.load(source)
        trace = first_value["value"]
        descriptors = {item["name"]: item["count"] for item in first_value["arrays"]}
        for name in descriptors:
            trace[name] = []
        for line_number, line in enumerate(source, 2):
            item = json.loads(line)
            if item.get("record") != "item" or item.get("section") not in descriptors:
                raise ValueError(f"invalid JSONL record at line {line_number}")
            section = item["section"]
            if item.get("index") != len(trace[section]):
                raise ValueError(f"out-of-order {section} item at line {line_number}")
            trace[section].append(item["value"])
        for name, count in descriptors.items():
            if len(trace[name]) != count:
                raise ValueError(f"{name} count mismatch: expected {count}, got {len(trace[name])}")
        return trace


def code_artifact_ids(path):
    data = open(path, "rb").read()
    header = struct.unpack_from("<QIIIIQQQQII", data)
    if header[0] != 0x0045444F43484556 or header[1] != 1 or header[2] != 64:
        raise ValueError("invalid .vtc header")
    if len(data) != 64 + header[8]:
        raise ValueError(".vtc record length mismatch")
    cursor, ids, code_bytes = 64, set(), 0
    for _ in range(header[9]):
        record = struct.unpack_from("<QQQQQII", data, cursor)
        cursor += 48
        ids.add(record[5])
        cursor += record[6]
        code_bytes += record[6]
    if cursor != len(data) or code_bytes != header[7]:
        raise ValueError("invalid .vtc record stream")
    return ids


def validate(trace, trace_path, code_artifact_override=None):
    if trace.get("schema_version") != 4 or trace.get("mode") != "aggregated":
        raise ValueError("expected schema_version=4 mode=aggregated")
    thread_id = trace.get("thread_id")
    for section in ("events", "memory_events", "register_events"):
        events = trace.get(section, [])
        sequences = [item["sequence"] for item in events]
        if sequences != sorted(sequences):
            raise ValueError(f"{section} sequences are not ordered")
        if any(item.get("thread_id") != thread_id for item in events):
            raise ValueError(f"{section} contains another thread")
    version_ids = {item["id"] for item in trace.get("code_versions", [])}
    capture = trace.get("code_capture", {})
    if capture.get("storage") == "file" and capture.get("path"):
        artifact_path = code_artifact_override or capture["path"]
        if not os.path.isabs(artifact_path):
            artifact_path = os.path.join(os.path.dirname(os.path.abspath(trace_path)), artifact_path)
        version_ids = code_artifact_ids(artifact_path)
    missing = sorted({item["code_version"] for item in trace.get("events", [])
                      if "code_version" in item} - version_ids)
    if missing:
        raise ValueError(f"events reference missing code versions: {missing[:8]}")
    return {
        "path": os.path.abspath(trace_path),
        "sha256": hashlib.sha256(open(trace_path, "rb").read()).hexdigest(),
        "thread_id": thread_id,
        "stop_reason": trace.get("stop_reason"),
        "steps_executed": trace.get("steps_executed"),
        "counts": {name: len(trace.get(name, [])) for name in
                   ("blocks", "edges", "events", "memory_events", "register_events", "code_versions")},
        "occurrence_window": trace.get("occurrence_window"),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace")
    parser.add_argument("--sha256", help="expected lowercase or uppercase SHA-256")
    parser.add_argument("--code-artifact", help="local .vtc path overriding the captured host path")
    args = parser.parse_args()
    trace = load_trace(args.trace)
    summary = validate(trace, args.trace, args.code_artifact)
    if args.sha256 and summary["sha256"].lower() != args.sha256.lower():
        raise SystemExit("trace SHA-256 mismatch")
    print(json.dumps(summary, separators=(",", ":")))


if __name__ == "__main__":
    main()
