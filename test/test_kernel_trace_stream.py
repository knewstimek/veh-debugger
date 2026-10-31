"""Streaming KD fixture: large facts stay in files and every MCP reply is bounded."""
import hashlib
import json
import pathlib
import struct
import tempfile

from build_paths import RELEASE
from owned_mcp_client import OwnedMcpClient
from test_kernel_debug_protocol import Stub

HEADER=struct.Struct("<IIQIIIIQII")
HEADER2=struct.Struct("<IIQIIIIQIIQQII")
COMPACT=struct.Struct("<3Q3I4B16s")
FILE=struct.Struct("<8sIIQQIIQQQ")

class StreamStub(Stub):
    def __init__(self):
        self.generation=0;self.limit=0;self.offset=0;self.count=0;self.flags=0;self.end=1
        self.resumes=0;self.delivered=0;self.fail_at=None;self.bad=None;self.bad_crc_at=None
        super().__init__()
    def status(self):
        count=self.count;steps=self.offset+count;offset=self.offset;cpu=0
        if self.bad=="offset" and self.offset:offset-=1
        if self.bad=="steps" and self.offset:steps-=1
        if self.bad=="cpu" and self.offset:cpu=1
        size=200 if self.flags&1 else 56
        return (2,size,self.generation,count,steps,self.end,self.flags,0x1000,cpu,0,offset,self.limit,int(self.end==8),0)
    def next_chunk(self):
        self.count=min(4096,self.limit-self.offset)
        self.end=8 if self.offset+self.count<self.limit else 1
    def packet(self,text):
        self.commands.append(text)
        if text=="qC":self.send("QC1")
        elif text=="qTraceBB:cap":self.send("1,1000")
        elif text=="qTraceBB:cap2":self.send("2,1000,4c4b40")
        elif text=="qTraceBB:status":self.send(HEADER.pack(*self.status()[:10]).hex())
        elif text=="qTraceBB:status2":self.send(HEADER2.pack(*self.status()).hex())
        elif text.startswith("vTraceBB:2,"):
            self.generation+=1;fields=text.split(",");self.limit=int(fields[1],16);self.flags=int(fields[4],16)
            self.offset=0;self.delivered=0;self.resumes=0;self.next_chunk();self.send("T05thread:01;")
        elif text.startswith("qTraceBB:read2,"):
            _,generation,offset,count=text.split(",")
            offset=int(offset,16);count=int(count,16)
            assert int(generation,16)==self.generation and self.offset<=offset and offset+count<=self.offset+self.count
            if self.fail_at is not None and offset>=self.fail_at:self.send("E01");return
            if offset<=self.delivered:self.delivered=max(self.delivered,offset+count)
            base=COMPACT.pack(0x1000,0x1000,0x2000,0,0,0,64,0,2,0,b"\xeb\xfe".ljust(16,b"\0"))
            if self.flags&1:
                regs=[0]*18;regs[0]=7;regs[16]=0x1000;regs[17]=0x202;base+=struct.pack("<18Q",*regs)
            payload=(base*count).hex()
            if self.bad_crc_at is not None and offset>=self.bad_crc_at:
                wire=payload.encode();self.peer.sendall(b"$"+wire+b"#"+f"{(sum(wire)+1)&255:02x}".encode())
            else:self.send(payload)
        elif text.startswith("vTraceBB:resume2,"):
            _,generation,offset=text.split(",")
            assert int(generation,16)==self.generation and int(offset,16)==self.offset+self.count==self.delivered
            self.resumes+=1;self.offset+=self.count;self.next_chunk();self.send("T05thread:01;")
        elif text.startswith("qTraceBB:cancel2,"):
            assert int(text.split(",")[1],16)==self.generation
            self.end=3;self.send("OK")
        else:
            self.commands.pop()
            super().packet(text)

def run():
    stub=StreamStub();client=None;artifacts=[];checks=0
    exports=tempfile.TemporaryDirectory(prefix="veh-kd-stream-export-")
    export_root=pathlib.Path(exports.name).resolve()
    def check(ok,description,detail=None):
        nonlocal checks
        assert ok,(description,str(detail)[:500])
        checks+=1
    def capture(**kwargs):
        args={"execution_context":"kd","start":"0x1000","end":"0x1002","max_steps":100000,
            "timeout_ms":60000,"collect_snapshots":False,**kwargs}
        result=client.tool("veh_trace_basic_blocks",args)
        if "capture_file" in result:artifacts.append(result["capture_file"]["path"])
        return result
    try:
        client=OwnedMcpClient();client.initialize()
        check(client.tool("veh_kd_connect",{"transport":"tcp","address":f"127.0.0.1:{stub.port}"}).get("halted"),"connect")
        result=capture(collect_code=True,collect_events=True)
        check(result.get("steps_executed")==100000 and result.get("chunks")==25 and stub.resumes==24,"one logical100k capture",result)
        check(len(json.dumps(result).encode())<=8192 and "events" not in result and "blocks" not in result,"bounded summary",result)
        artifact=result["capture_file"];path=pathlib.Path(artifact["path"])
        check(artifact["records"]=="100000" and path.stat().st_size==64+100000*200,"all records in artifact",artifact)
        check(hashlib.sha256(path.read_bytes()).hexdigest()==artifact["sha256"],"artifact hash")
        with path.open("rb") as f:header=FILE.unpack(f.read(64))
        check(header[0]==b"VEHKDTR2" and header[3]==100000,"portable artifact header")
        page_args={"execution_context":"kd","operation":"read_capture","capture_file":str(path),"offset":"99990","limit":100}
        page=client.tool("veh_trace_basic_blocks",page_args)
        check(page.get("count")==10 and page.get("next_offset") is None and page["records"][0]["sequence"]=="99991","last page exact",page)
        check(len(json.dumps(page).encode())<=8192,"bounded record page")
        filtered=client.tool("veh_trace_basic_blocks",{**page_args,"offset":"0","address_start":"0x2000","address_end":"0x3000"})
        check(filtered.get("count")==0 and filtered.get("scan_limited") and filtered.get("next_offset")=="65536","bounded range scan",filtered)
        batch=client.tool("veh_batch",{"steps":[{"tool":"veh_trace_basic_blocks","args":page_args}]})
        check(batch.get("error")=="Not attached","batch retains its process-attachment requirement",batch)
        starts=sum(p.startswith("vTraceBB:2,") for p in stub.commands)
        rejected=client.tool("veh_batch",{"steps":[{"tool":"veh_trace_basic_blocks","args":{"execution_context":"kd","start":"0x1000","end":"0x1002"}}]})
        check("error" in rejected and sum(p.startswith("vTraceBB:2,") for p in stub.commands)==starts,"capture has no nested execution effects",rejected)
        stub.fail_at=5000
        failed=capture(max_steps=10000)
        check("error" in failed and failed.get("copied_records")=="4096" and failed.get("backend_buffer_retained"),"copy failure preserves both sides",failed)
        check(pathlib.Path(failed["capture_file"]["path"]).stat().st_size>=64+4096*200 and stub.resumes==1,"acknowledged prefix retained",failed)
        stub.fail_at=None
        stub.bad_crc_at=5000
        corrupt=capture(max_steps=10000)
        check("error" in corrupt and corrupt.get("copied_records")=="4096" and stub.resumes==1,"corrupted packet never becomes an observation",corrupt)
        stub.bad_crc_at=None
        short=capture(max_steps=100000,timeout_ms=1)
        check(short.get("timeout_requested") and short.get("stop_reason")=="interrupted" and
            short.get("steps_executed")==4096 and stub.resumes==0,"global deadline cancels before next execution",short)
        for bad in ("offset","steps","cpu"):
            stub.bad=bad;failed=capture(max_steps=9000)
            check("error" in failed and failed.get("capture_incomplete"),"malformed continuation "+bad,failed)
        stub.bad=None
        # Existing explicit export consumers keep their object contract and metadata.
        for encoding in ("json","jsonl"):
            output=export_root/("trace."+encoding)
            exported=capture(max_steps=10,output_file=str(output),output_format=encoding)
            metadata=exported["output_file"];raw=output.read_bytes()
            check(isinstance(metadata,dict) and metadata["path"]==str(output) and metadata["format"]==encoding,
                "explicit export object contract "+encoding,exported)
            check(metadata["size"]==len(raw) and metadata["sha256"]==hashlib.sha256(raw).hexdigest(),
                "explicit export hash "+encoding,metadata)
        full=capture(max_steps=20,collect_snapshots=True,output_file=str(export_root/"snapshots.json"))
        full_page=client.tool("veh_trace_basic_blocks",{"execution_context":"kd","operation":"read_capture",
            "capture_file":full["capture_file"]["path"],"offset":"0","limit":2,"include_registers":True})
        check(full_page.get("count")==2 and full_page["records"][0]["registers"][0]=="0x7"
            and full_page["records"][0]["registers"][16]=="0x1000","full wire register layout preserved",full_page)
        # Reject Win32 truncation and response-amplifying metadata before opening a file.
        for invalid in (str(path)+"\0"+"\x01"*2000,str(path)+"\x1f",str(path)+"\x7f"):
            refused=client.tool("veh_trace_basic_blocks",{**page_args,"capture_file":invalid})
            check("error" in refused and len(json.dumps(refused).encode())<=8192,
                "control path rejected with bounded reply",refused)
        starts=sum(p.startswith("vTraceBB:2,") for p in stub.commands)
        invalid_output=str(export_root/"bad.json")+"\0ignored"
        refused=capture(max_steps=10,output_file=invalid_output)
        check("error" in refused and sum(p.startswith("vTraceBB:2,") for p in stub.commands)==starts
            and not (export_root/"bad.json").exists(),"invalid output refused before capture",refused)
        # Pure artifact reads work offline through attached batch and BP actions.
        attached=client.tool("veh_attach",{"pid":4242,"target_scope":"guest",
            "agent":str(pathlib.Path(RELEASE)/"guest_backend_fixture.exe"),
            "agent_args":["--metadata","path-file-output"]})
        check(attached.get("success"),"attach process fixture for read parity",attached)
        batch=client.tool("veh_batch",{"steps":[{"tool":"veh_trace_basic_blocks","args":page_args}]})
        check(batch.get("failed")==0 and batch["results"][0]["result"]==page,
            "artifact read direct/batch parity",batch)
        installed=client.tool("veh_set_breakpoint",{"address":"0x1000","action":[
            {"tool":"veh_trace_basic_blocks","args":page_args},
            {"tool":"veh_set_breakpoint","args":{"address":"$0.records.0.cr3"}}]})
        check(installed.get("id"),"install artifact read action",installed)
        check(client.tool("veh_continue").get("success"),"start artifact read action")
        client.wait_notification("notifications/logging",lambda p:"Breakpoint #7 hit" in p.get("data",""),timeout=15)
        listed=client.tool("veh_list_breakpoints")
        check(any(int(row["address"],0)==0x2000 for row in listed["software"]),
            "artifact read action result reference",{"listed":listed,"stderr":client.stderr_tail()[-1600:]})
        check(sum(p.startswith("vTraceBB:2,") for p in stub.commands)==starts,
            "artifact reads never execute a KD capture")
        nested=client.tool("veh_batch",{"steps":[{"tool":"veh_trace_basic_blocks","args":{
            "execution_context":"kd","start":"0x1000","end":"0x1002"}}]})
        check(nested.get("failed")==1 and sum(p.startswith("vTraceBB:2,") for p in stub.commands)==starts,
            "attached batch still excludes whole-machine capture",nested)
        check(client.tool("veh_detach").get("success"),"detach process fixture")
        print(f"PASS streamed KD {checks} checks;100000 facts in artifact, replies<=8KiB, immutable offsets and failure retention")
    finally:
        try:
            if client is not None:
                try:client.tool("veh_kd_disconnect")
                finally:client.close(terminate_target=False)
        finally:
            try:stub.close()
            finally:
                try:
                    temporary=pathlib.Path(tempfile.gettempdir()).resolve()
                    for text in artifacts:
                        path=pathlib.Path(text).resolve()
                        assert (path.parent==temporary and path.name.lower().startswith("vkd")) or path.is_relative_to(export_root),"Outside owned capture temp path"
                        path.unlink(missing_ok=True)
                finally:exports.cleanup()

if __name__=="__main__":run()
