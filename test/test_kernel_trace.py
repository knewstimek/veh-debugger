"""Bounded KD capture receipts through the real MCP frontend; no guest execution."""
import struct
from mcp_test_client import McpClient
from test_kernel_debug_protocol import Stub

HEADER=struct.Struct("<IIQIIIIQII")
RECORD=struct.Struct("<3Q18Q3I4B16s")

class TraceStub(Stub):
    def __init__(self):
        self.generation=0
        self.flags=0
        self.records=[]
        self.bad_receipt=False
        self.receipt_mode=""
        self.supported=True
        super().__init__()

    def packet(self,text):
        if text=="qC":
            self.commands.append(text);self.send("QC1")
        elif text=="qTraceBB:cap":
            self.commands.append(text);self.send("1,1000" if self.supported else "")
        elif text=="qTraceBB:status":
            self.commands.append(text)
            self.send(HEADER.pack(1,200,self.generation,len(self.records),len(self.records),1,self.flags,
                0x1006,0,0).hex())
        elif text.startswith("vTraceBB:"):
            self.commands.append(text)
            self.generation+=1
            self.flags=int(text.rsplit(",",1)[1],16)
            self.records=[]
            # mov eax,1; add eax,2. One observed straight-line block, not two guessed branches.
            for address,next_address,code in ((0x1000,0x1005,b"\xb8\x01\x00\x00\x00"),(0x1005,0x1008,b"\x83\xc0\x02")):
                regs=[0]*18;regs[0]=1;regs[16]=address;regs[17]=0x202
                self.records.append(RECORD.pack(address,next_address,0x1000,*regs,0,0,0,64,0,len(code),0,code.ljust(16,b"\0")))
            # The stop receipt must agree exactly with the last observed destination.
            self.send("T05thread:01;")
        elif text.startswith("qTraceBB:read,"):
            self.commands.append(text)
            _,gen,offset,count=text.split(",")
            assert int(gen,16)==self.generation
            payload=b"".join(self.records[int(offset,16):int(offset,16)+int(count,16)])
            self.send(payload.hex()[:-2] if self.bad_receipt else payload.hex())
        else:
            super().packet(text)

def run():
    # Header finalAddress is customized here to the observed final PC.
    class GoodTraceStub(TraceStub):
        def packet(self,text):
            if text=="qTraceBB:status":
                self.commands.append(text)
                count=1 if self.receipt_mode=="short_budget" and self.generation else len(self.records)
                end=2 if self.receipt_mode=="range_inside" and self.generation else 1
                cpu=1 if self.receipt_mode=="wrong_cpu" and self.generation else 0
                self.send(HEADER.pack(1,200,self.generation,count,count,end,self.flags,0x1008,cpu,0).hex())
            else: super().packet(text)
    stub=GoodTraceStub();client=None
    args={"execution_context":"kd","start":"0x1000","end":"0x2000","max_steps":2,"collect_code":True}
    try:
        client=McpClient();client.initialize()
        assert client.tool("veh_kd_connect",{"transport":"tcp","address":f"127.0.0.1:{stub.port}"}).get("halted")
        result=client.tool("veh_trace_basic_blocks",args)
        assert result.get("steps_executed")==2 and result.get("final_address")=="0x1008",result
        assert result.get("halted") and len(result["blocks"])==1 and result["blocks"][0]["end"]=="0x1008",result
        assert result["events"][0]["thread_id"] is None and result["collection"]["snapshots"],result
        starts=sum(p.startswith("vTraceBB:") for p in stub.commands)
        for key,value in (("compress_paths",True),("stack_bytes",8),("threadId",1),("collect_code","yes"),("max_steps",4097),("dependency_sources",["rax"]),("max_event_file_bytes",88)):
            rejected=client.tool("veh_trace_basic_blocks",{**args,key:value})
            assert "error" in rejected,(key,rejected)
        assert sum(p.startswith("vTraceBB:") for p in stub.commands)==starts
        stub.bad_receipt=True
        bad=client.tool("veh_trace_basic_blocks",args)
        assert bad.get("capture_incomplete") and bad.get("halted"),bad
        stub.bad_receipt=False
        for mode in ("short_budget","range_inside","wrong_cpu"):
            stub.receipt_mode=mode
            bad=client.tool("veh_trace_basic_blocks",args)
            assert "error" in bad and bad.get("halted"),(mode,bad)
        stub.receipt_mode=""
        before=sum(p.startswith("vTraceBB:") for p in stub.commands)
        bad=client.tool("veh_trace_basic_blocks",{**args,"cpu":10})
        assert "error" in bad and "Hgb" in stub.commands,bad
        assert sum(p.startswith("vTraceBB:") for p in stub.commands)==before
        stub.supported=False
        rejected=client.tool("veh_trace_basic_blocks",args)
        assert rejected.get("code")=="unsupported_backend",rejected
        assert not any(p.startswith("m") or p.startswith("vCont;s") for p in stub.commands),stub.commands
        print("PASS KD backend capture, block shaping, unknown thread identity, pre-effect policies and malformed pages")
    finally:
        if client is not None:
            try: client.tool("veh_kd_disconnect")
            finally: client.close(terminate_target=False)
        stub.close()

if __name__=="__main__":run()
