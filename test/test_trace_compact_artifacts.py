"""Actual MCP file/compact boundary against a host-owned synthetic IPC peer.
No VM operations, guest helpers or existing MCP sessions are involved.
"""
import hashlib
import json
import os
from pathlib import Path
import tempfile

def main():
    from build_paths import RELEASE
    from owned_mcp_client import OwnedMcpClient
    binaries=Path(RELEASE).resolve()
    generated=[]
    sizes=[]
    try:
        with tempfile.TemporaryDirectory(prefix="trace-mcp-fixture-") as temporary:
            with OwnedMcpClient(executable=str(binaries/"veh-mcp-server.exe")) as client:
                client.initialize("compact-trace-artifacts")
                attached=client.tool("veh_attach",{
                    "pid":424242,"agent":str(binaries/"guest_backend_fixture.exe"),
                    "target_scope":"guest","agent_args":["--metadata","path-stream-compact"]})
                assert attached.get("success"),attached
                common={"threadId":77,"start":"0x1000","end":"0x1010","max_steps":1000,
                        "collect_register_events":True,"collect_memory_events":True}
                def check(result):
                    for name in ("output_file","event_file"):
                        if isinstance(result.get(name),dict) and result[name].get("path"):
                            generated.append(Path(result[name]["path"]).resolve())
                    assert result.get("mode")=="file" and "error" not in result,result
                    assert len(json.dumps(result).encode())<8192
                    sizes.append(len(json.dumps(result).encode()))
                    assert result["counts"]["register_events"]==300,result
                    assert result["counts"]["memory_events"]==300,result
                    assert not any(result["drop_counts"].values()),result
                    assert not any(result["truncation"].values()),result
                    output=result["output_file"]
                    assert output["complete"] and output["format"]=="json",output
                    assert output["storage_complete"] and output["capture_complete"],output
                    raw=Path(output["path"]).read_bytes()
                    assert hashlib.sha256(raw).hexdigest()==output["sha256"]
                    saved=json.loads(raw)
                    assert "register_events" not in saved and "memory_events" not in saved
                    event=Path(result["event_file"]["path"])
                    assert event.exists() and event.stat().st_size>100000
                    return result
                # Default large collection chooses events_output=file itself.
                direct=check(client.tool("veh_trace_basic_blocks",dict(common,
                    events_output_path=str(Path(temporary)/"direct.vte"))))
                batch=client.tool("veh_batch",{"steps":[{"tool":"veh_trace_basic_blocks","args":dict(common,
                    events_output_path=str(Path(temporary)/"batch.vte"))}]})
                assert batch["failed"]==0,batch
                check(batch["results"][0]["result"])
                assert batch["results"][0]["result"]["counts"]==direct["counts"]
                action_path=Path(temporary)/"action.json"
                installed=client.tool("veh_set_breakpoint",{"address":"0x1000","action":[
                    {"tool":"veh_trace_basic_blocks","args":dict(common,
                     events_output_path=str(Path(temporary)/"action.vte"),output_file=str(action_path))}]})
                assert installed.get("id"),installed
                assert client.tool("veh_continue").get("success")
                client.wait_notification("notifications/logging",
                    lambda p:"Breakpoint #7 hit" in p.get("data",""),timeout=15)
                saved=json.loads(action_path.read_bytes())
                assert "register_events" not in saved and saved["event_file"]["counts"]["register_events"]==300,saved
                assert len(client.notifications)<20,"Per-record MCP notification flooding"
                assert client.tool("veh_detach").get("success")
                # Preserve a small explicit legacy inline request shape.
                attached=client.tool("veh_attach",{
                    "pid":424242,"agent":str(binaries/"guest_backend_fixture.exe"),
                    "target_scope":"guest","agent_args":["--metadata","path-good"]})
                assert attached.get("success"),attached
                small=client.tool("veh_trace_basic_blocks",{"threadId":77,"start":"0x1000","end":"0x1010",
                    "max_steps":16,"collect_events":True,"collect_snapshots":False,"output_mode":"inline",
                    "collect_code":True,"compress_paths":True,"events_output":"inline"})
                assert "error" not in small and small.get("mode")!="file",small
                assert len(small["events"])==2,small
                assert client.tool("veh_detach").get("success")
                attached=client.tool("veh_attach",{
                    "pid":424242,"agent":str(binaries/"guest_backend_fixture.exe"),
                    "target_scope":"guest","agent_args":["--metadata","path-large-json"]})
                assert attached.get("success"),attached
                oversized=client.tool("veh_trace_basic_blocks",{"threadId":77,"start":"0x1000","end":"0x1010",
                    "max_steps":200,"collect_register_events":True,"events_output":"inline","output_mode":"inline"})
                if isinstance(oversized.get("output_file"),dict) and oversized["output_file"].get("path"):
                    generated.append(Path(oversized["output_file"]["path"]).resolve())
                assert oversized.get("mode")=="file",oversized
                raw=Path(oversized["output_file"]["path"]).read_bytes()
                assert len(raw)>65536 and len(json.dumps(oversized).encode())<8192
                assert len(json.loads(raw)["register_events"])==200
                assert client.tool("veh_detach").get("success")
    finally:
        root=Path(tempfile.gettempdir()).resolve()
        for path in generated:
            assert path.is_relative_to(root),"Fixture output escaped temporary storage"
            path.unlink(missing_ok=True)
    print(json.dumps({"direct_batch_action":"passed","oversized_inline_guard":"passed","automatic_file_stream":True,
        "compact_reply_bytes":sizes,"legacy_small_inline":"preserved",
        "notification_flood":False,"fixture_process_cleanup":"owned_job",
        "VM_qualification":False}))
if __name__=="__main__":
    main()
