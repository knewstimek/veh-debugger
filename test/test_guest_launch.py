"""Host-owned MCP bootstrap qualification. Never touches a VM or existing server."""
import json
import os
from pathlib import Path
import tempfile

def main():
    from build_paths import RELEASE
    from owned_mcp_client import OwnedMcpClient
    binaries=Path(RELEASE).resolve()
    generated=[]
    try:
        with tempfile.TemporaryDirectory(prefix="launch-mcp-fixture-") as temporary:
            folder=Path(temporary)
            profile=folder/"backends.json"
            names=["launch-32","launch-64","launch-bad-nonce","launch-wrong-pid","launch-no-child"]
            profile.write_text(json.dumps({name:{"path":str(binaries/"guest_backend_fixture.exe"),
                "args":["--metadata",name],"target_scope":"guest","guest_launch":True} for name in names}),encoding="utf-8")
            environment=dict(os.environ,VEH_BACKENDS=str(profile),TMP=temporary,TEMP=temporary)
            common={"program":"Q:\\guest only\\sample.exe","cwd":"Q:\\guest only",
                "args":["","a b","한글",'quote"tail']}
            for bits,stop in [(32,True),(64,False)]:
                with OwnedMcpClient(executable=str(binaries/"veh-mcp-server.exe"),env=environment) as client:
                    client.initialize("guest-launch-bootstrap")
                    # Inline peers never opt into a side-effecting bootstrap.
                    denied=client.tool("veh_launch",dict(common,agent=str(binaries/"guest_backend_fixture.exe"),target_scope="guest"))
                    assert "error" in denied,denied
                    denied=client.tool("veh_launch",dict(common,backend="launch-"+str(bits),runAsInvoker=True))
                    assert "error" in denied,denied
                    assert not list(folder.glob("hvguest-*")),"Unsupported options created a request"
                    denied=client.tool("veh_launch",dict(common,backend="launch-"+str(bits),args=["bad\u0000tail"]))
                    assert "error" in denied,denied
                    assert not list(folder.glob("hvguest-*")),"Invalid text created a request"
                    denied=client.tool("veh_launch",dict(common,backend="launch-"+str(bits),env=["bad"]))
                    assert "error" in denied and not list(folder.glob("hvguest-*")),denied
                    request=dict(common,backend="launch-"+str(bits),stopOnEntry=stop,
                        env={"PATH":"guest-new","EMPTY":"","UNICODE":"한글"})
                    if bits == 64:
                        batch=client.tool("veh_batch",{"steps":[{"tool":"veh_launch","args":request}]})
                        assert batch["failed"] == 0, batch
                        result=batch["results"][0]["result"]
                    else:
                        result=client.tool("veh_launch",request)
                    assert result.get("success") and result["pid"]==424242 and result["addressBits"]==bits,result
                    assert result["mainThreadId"]==77 and result["backend"]["targetScope"]=="guest",result
                    assert not list(folder.glob("hvguest-*")),"Verified request not cleaned"
                    for peer_policy in (False,True):
                        denied=client.tool("veh_trace_basic_blocks",{"threadId":77,"start":"0x1000","end":"0x1010",
                            "max_steps":1,"run_peer_cpus":peer_policy})
                        assert denied.get("code")=="unsupported_policy" and "only for KD" in denied.get("error",""),denied
                    if stop:
                        refused=client.tool("veh_trace_basic_blocks",{"threadId":77,"start":"0x1000","end":"0x1010",
                            "max_steps":1000,"collect_register_events":True,"follow_exceptions":True})
                        assert "error" in refused,refused
                        capture=client.tool("veh_trace_basic_blocks",{
                            "threadId":77,"start":"0x1000","end":"0x1010","max_steps":1000,
                            "collect_register_events":True,"collect_memory_events":True,"follow_exceptions":False,
                            "output_mode":"file","output_file":str(folder/"launch-trace.json"),
                            "events_output_path":str(folder/"launch-trace.vte")})
                        assert "error" not in capture and capture.get("mode")=="file",capture
                        assert capture["event_file"]["counts"]["register_events"]==300,capture
                        assert capture["event_file"]["counts"]["memory_events"]==300,capture
                        assert len(json.dumps(capture).encode())<=8192,"MCP trace response exceeds8KiB"
                        assert Path(capture["event_file"]["path"]).stat().st_size>100000
                    threads=client.tool("veh_threads")
                    assert "resumed:"+str(0 if stop else 1) in json.dumps(threads),threads
                    assert len(client.notifications)<20,"Unexpected notification flooding"
                    assert client.tool("veh_detach").get("success")
            for name in ["launch-bad-nonce","launch-wrong-pid","launch-no-child"]:
                with OwnedMcpClient(executable=str(binaries/"veh-mcp-server.exe"),env=environment) as client:
                    client.initialize("guest-launch-refusal")
                    result=client.tool("veh_launch",dict(common,backend=name))
                    assert "error" in result,result
                    retained=list(folder.glob("hvguest-*.req"))
                    if name=="launch-no-child":
                        assert not retained,"Exact no-submission result must permit retry"
                        retry=client.tool("veh_launch",dict(common,backend="launch-32"))
                        assert retry.get("success"),retry
                        assert client.tool("veh_detach").get("success")
                    else:
                        assert len(retained)==1,"Ambiguous request must be retained"
                        again=client.tool("veh_launch",dict(common,backend="launch-32"))
                        assert "Previous guest launch outcome retained" in again.get("error",""),again
                        assert list(folder.glob("hvguest-*.req"))==retained,"Ambiguous launch was replayed"
                        for path in folder.glob("hvguest-*"):
                            generated.append(path)
                # Only this fixture's private temporary directory is cleaned.
                for path in generated:
                    assert path.parent==folder and path.name.startswith("hvguest-")
                    path.unlink(missing_ok=True)
                generated.clear()
        print("frontend_guest_launch: x86/x64, entry/continue, UTF16 args/env, explicit opt-in, nonce/metadata refusal, no-replay and owned cleanup passed")
    finally:
        for path in generated:
            if path.exists():path.unlink()

if __name__=="__main__":main()
