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
        self.policies="";self.terminal=None;self.record_fault=None;self.status_error=False;self.read_error=False
        self.peer_stop=False;self.refuse=False;self.cancel_fault=None
        super().__init__()
    def status(self):
        count=self.count;steps=self.offset+count;offset=self.offset;cpu=0
        if self.bad=="offset" and self.offset:offset-=1
        if self.bad=="steps" and self.offset:steps-=1
        if self.bad=="cpu" and self.offset:cpu=1
        size=200 if self.flags&1 else 56
        flags=self.flags ^ (2 if (self.bad=="flags" and self.offset) or self.bad=="start_flags" or
            (self.cancel_fault=="flags" and self.end==3) else 0)
        if self.bad=="empty_unknown" and self.end==9:count=0;steps=self.offset
        final=0x1001 if self.end==9 else 0x1800 if self.end==10 else 0x1000
        return (2,size,self.generation,count,steps,self.end,flags,final,cpu,0,offset,self.limit,int(self.end==8),0)
    def next_chunk(self):
        self.count=min(4096,self.limit-self.offset)
        self.end=8 if self.offset+self.count<self.limit else (self.terminal or 1)
        if self.end==10:self.count-=1
    def packet(self,text):
        self.commands.append(text)
        if text=="qC":self.send("QC1")
        elif text=="qTraceBB:cap":self.send("1,1000")
        elif text=="qTraceBB:cap2":self.send("2,1000,4c4b40")
        elif text=="qTraceBB:policies2":self.send(self.policies)
        elif text=="qTraceBB:status":self.send(HEADER.pack(*self.status()[:10]).hex())
        elif text=="qTraceBB:status2":self.send("E23" if (self.status_error and self.offset) or
            (self.cancel_fault=="E23" and self.end==3) else HEADER2.pack(*self.status()).hex())
        elif text.startswith("vTraceBB:2,"):
            if self.refuse:self.send("E22");return
            self.generation+=1;fields=text.split(",");self.limit=int(fields[1],16);self.flags=int(fields[4],16)
            self.offset=0;self.delivered=0;self.resumes=0;self.next_chunk();self.send("T05thread:02;" if self.peer_stop else "T05thread:01;")
        elif text.startswith("qTraceBB:read2,"):
            _,generation,offset,count=text.split(",")
            offset=int(offset,16);count=int(count,16)
            assert int(generation,16)==self.generation and self.offset<=offset and offset+count<=self.offset+self.count
            if self.fail_at is not None and offset>=self.fail_at:self.send("E01");return
            if self.read_error and self.offset:self.send("E23");return
            if offset<=self.delivered:self.delivered=max(self.delivered,offset+count)
            rows=[]
            for index in range(offset,offset+count):
                last=index+1==self.offset+self.count
                uncertain=self.end==9 and last
                if self.record_fault=="early" and index==self.offset:uncertain=True
                if self.record_fault=="marker_on_normal" and last:uncertain=True
                if self.record_fault=="missing" and uncertain:uncertain=False
                code=b"\0"*16 if uncertain else b"\xeb\xfe".ljust(16,b"\0")
                if self.record_fault=="nonzero" and uncertain:code=b"\x90"+b"\0"*15
                reserved=(2 if self.record_fault=="reserved" else 1) if uncertain else 0
                next_pc=0x1001 if self.end==9 and last else 0x1000
                if self.record_fault=="chain" and index==self.offset+1:next_pc=0x1001
                if self.record_fault=="final" and last:next_pc=0x1000
                base=COMPACT.pack(0x1000,next_pc,0x2000,0,0,0,64,0,0 if uncertain else 2,reserved,code)
                if self.flags&1:
                    regs=[0]*18;regs[0]=7;regs[16]=0x1000;regs[17]=0x202;base+=struct.pack("<18Q",*regs)
                rows.append(base)
            payload=b"".join(rows).hex()
            if self.bad_crc_at is not None and offset>=self.bad_crc_at:
                wire=payload.encode();self.peer.sendall(b"$"+wire+b"#"+f"{(sum(wire)+1)&255:02x}".encode())
            else:self.send(payload)
        elif text.startswith("vTraceBB:resume2,"):
            _,generation,offset=text.split(",")
            assert int(generation,16)==self.generation and int(offset,16)==self.offset+self.count==self.delivered
            self.resumes+=1;self.offset+=self.count;self.next_chunk();self.send("T05thread:02;" if self.peer_stop else "T05thread:01;")
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
        # Policy negotiation must never change default execution or silently fall back.
        check("qTraceBB:policies2" not in stub.commands and stub.flags in (0,1),
            "default never requests peer execution")
        for reply in ("","E22","3,3","2,1","2","2,3,1","0x2,3","2,+3","2, 3","2,10000000000000000"):
            stub.policies=reply
            starts=sum(p.startswith("vTraceBB:2,") for p in stub.commands)
            refused=capture(max_steps=10,run_peer_cpus=True)
            check(refused.get("code")=="unsupported_policy" and
                sum(p.startswith("vTraceBB:2,") for p in stub.commands)==starts,
                "unsupported/malformed policy has no execution effects "+repr(reply),refused)
        stub.policies="2,2"
        starts=sum(p.startswith("vTraceBB:2,") for p in stub.commands)
        refused=capture(max_steps=10,run_peer_cpus=True,collect_snapshots=True)
        check(refused.get("code")=="unsupported_policy" and
            sum(p.startswith("vTraceBB:2,") for p in stub.commands)==starts,
            "all requested policy flags must be advertised",refused)
        stub.policies="2,3"
        for snapshots in (False,True):
            good=capture(max_steps=10,run_peer_cpus=True,collect_snapshots=snapshots)
            check(good.get("applied_flags")==2+int(snapshots) and good.get("run_peer_cpus") and
                not good.get("capture_incomplete") and stub.flags==2+int(snapshots),
                "explicit policy flags with snapshots "+str(snapshots),good)
        starts=sum(p.startswith("vTraceBB:2,") for p in stub.commands)
        for value in (1,"true",None):
            refused=capture(max_steps=10,run_peer_cpus=value)
            check("error" in refused and sum(p.startswith("vTraceBB:2,") for p in stub.commands)==starts,
                "policy requires strict boolean",refused)
        for terminal in (9,10):
            stub.terminal=terminal
            for snapshots in (False,True):
                uncertain=capture(max_steps=4100,run_peer_cpus=True,collect_snapshots=snapshots,
                    collect_code=True,collect_events=True)
                check(uncertain.get("stop_reason")==("code_uncertain" if terminal==9 else "completion_uncertain") and
                    uncertain.get("capture_incomplete") and uncertain.get("decode_incomplete") and
                    uncertain.get("steps_executed")==4100-(terminal==10),
                    "uncertain capture accounting "+str((terminal,snapshots)),uncertain)
                a=uncertain["capture_file"]
                check(not a["complete"] and not a["capture_complete"] and a["storage_complete"] and
                    a["records"]==str(4100-(terminal==10)) and a["applied_flags"]==2+int(snapshots),
                    "incomplete capture has intact raw storage",a)
                saved=pathlib.Path(a["path"])
                check(hashlib.sha256(saved.read_bytes()).hexdigest()==a["sha256"],
                    "uncertain raw artifact hash")
                if terminal==9:
                    page_args={"execution_context":"kd","operation":"read_capture","capture_file":str(saved),
                        "offset":"4098","limit":100,"include_registers":True}
                    uncertain_page=client.tool("veh_trace_basic_blocks",page_args)
                    row=uncertain_page["records"][-1]
                    check(uncertain_page.get("count")==2 and row.get("code_uncertain") and
                        row.get("execution_code_verified") is False and "instruction" not in row and "bytes" not in row
                        and row["next_address"]=="0x1001" and len(json.dumps(uncertain_page).encode())<=8192,
                        "uncertain code page never disassembles",uncertain_page)
                    with saved.open("rb") as f:
                        f.seek(64+4099*200);raw_record=f.read(200)
                    check(raw_record[181:184]==bytes((0,0,1)) and raw_record[184:]==bytes(16),
                        "raw unknown code marker preserved")
                    check(uncertain["analysis_steps"]==4099 and uncertain["analysis_steps_omitted"]==1,
                        "unknown instruction excluded from analysis",uncertain)
                else:
                    check(uncertain.get("execution_count_incomplete") and uncertain.get("execution_gap") and
                        uncertain.get("steps_executed_lower_bound")==4099 and uncertain.get("lost_records") is None and
                        uncertain["final_address"]=="0x1800",
                        "completion uncertainty reports actual PC and lower bound",uncertain)
        stub.terminal=10
        empty=capture(max_steps=1,run_peer_cpus=True)
        check(empty.get("steps_executed_lower_bound")==0 and empty.get("execution_count_incomplete") and
            empty["capture_file"]["records"]=="0" and empty["capture_file"]["storage_complete"],
            "unconfirmed first attempt has zero records and actual final PC",empty)
        # Preserve unknown code in explicit JSON and JSONL while keeping it out of arrays.
        stub.terminal=9
        for encoding in ("json","jsonl"):
            out=export_root/("uncertain."+encoding)
            exported=capture(max_steps=2,run_peer_cpus=True,collect_code=True,collect_events=True,
                output_file=str(out),output_format=encoding)
            payload=out.read_text(encoding="utf-8")
            document=json.loads(payload) if encoding=="json" else json.loads(payload.splitlines()[0])
            check(exported["counts"]["blocks"]==1 and exported["counts"]["code_versions"]==1 and
                exported["analysis_steps"]==1 and not exported["capture_file"]["complete"],
                "export excludes unknown instruction "+encoding,document)
        for terminal in (9,10):
            stub.terminal=terminal
            bad=capture(max_steps=4)
            check("error" in bad,"uncertain terminal forbidden without policy "+str(terminal),bad)
        stub.terminal=9
        for fault in ("early","missing","nonzero","reserved","final"):
            stub.record_fault=fault
            bad=capture(max_steps=4,run_peer_cpus=True)
            check("error" in bad,"strict unknown marker and final PC "+fault,bad)
        stub.terminal=10;stub.record_fault="chain"
        bad=capture(max_steps=4,run_peer_cpus=True)
        check("error" in bad,"completion gap never relaxes prefix chain",bad)
        stub.terminal=None;stub.record_fault="marker_on_normal"
        bad=capture(max_steps=4,run_peer_cpus=True)
        check("error" in bad,"unknown marker forbidden for ordinary terminal",bad)
        stub.record_fault=None
        for invalid in ("start_flags","empty_unknown"):
            stub.bad=invalid;stub.terminal=9
            bad=capture(max_steps=4,run_peer_cpus=True)
            check("error" in bad,"invalid start flags or empty unknown terminal "+invalid,bad)
        stub.terminal=None
        stub.bad="flags"
        bad=capture(max_steps=4100,run_peer_cpus=True)
        check("error" in bad and bad.get("copied_records")=="4096" and
            not bad["capture_file"]["complete"],"changed flags refuse continuation and retain prefix",bad)
        stub.bad=None
        for error_source in ("status_error","read_error"):
            setattr(stub,error_source,True)
            bad=capture(max_steps=4100,run_peer_cpus=True)
            check(bad.get("backend_error")=="E23" and bad.get("halted") is False and
                "final_address" not in bad and bad.get("copied_records")=="4096" and
                bad["capture_file"]["storage_complete"],
                "E23 never substitutes stale final PC "+error_source,bad)
            setattr(stub,error_source,False)
        for fault in ("E23","flags"):
            stub.cancel_fault=fault
            bad=capture(max_steps=100000,timeout_ms=1,run_peer_cpus=True)
            check("error" in bad and bad.get("copied_records")=="4096" and
                (fault!="E23" or (bad.get("backend_error")=="E23" and bad.get("halted") is False)),
                "paused cancellation validates final status "+fault,bad)
        stub.cancel_fault=None
        for terminal in (3,4,6):
            stub.terminal=terminal;stub.peer_stop=True
            stopped=capture(max_steps=10,run_peer_cpus=True)
            check(stopped.get("cpu")==0 and stopped.get("capture_incomplete") and
                stopped["capture_file"]["storage_complete"] and not stopped["capture_file"]["complete"] and
                "blocks" in stopped and "edges" in stopped,
                "peer stop CPU does not replace selected CPU "+str(terminal),stopped)
        stub.terminal=None;stub.peer_stop=False
        stub.refuse=True
        bad=capture(max_steps=10,run_peer_cpus=True)
        check("error" in bad,"backend E22 refusal never promotes prior capture",bad)
        stub.refuse=False
        # Pure artifact reads work offline through attached batch and BP actions.
        # Reuse the uncertain page so nested paths must preserve its no-decode marker.
        page=uncertain_page
        starts=sum(p.startswith("vTraceBB:2,") for p in stub.commands)
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
