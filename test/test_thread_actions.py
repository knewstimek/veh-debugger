"""Existing veh_threads control actions, native cleanup and unsupported peers."""
from pathlib import Path
import tempfile
import ctypes
from ctypes import wintypes

from owned_mcp_client import OwnedMcpClient
from test_page_breakpoints import setup, program, tool, KERNEL, AGENT, protect
from test_breakpoint_threads import start_worker


def native_threads(pid):
    class Entry(ctypes.Structure):
        _fields_=[("size",wintypes.DWORD),("usage",wintypes.DWORD),("tid",wintypes.DWORD),
                  ("pid",wintypes.DWORD),("base",wintypes.LONG),("delta",wintypes.LONG),("flags",wintypes.DWORD)]
    KERNEL.CreateToolhelp32Snapshot.argtypes=(wintypes.DWORD,wintypes.DWORD)
    KERNEL.CreateToolhelp32Snapshot.restype=wintypes.HANDLE
    snapshot=KERNEL.CreateToolhelp32Snapshot(4,0)
    assert snapshot and snapshot!=wintypes.HANDLE(-1).value
    ids=[];entry=Entry();entry.size=ctypes.sizeof(entry)
    try:
        more=KERNEL.Thread32First(snapshot,ctypes.byref(entry))
        while more:
            if entry.pid==pid:ids.append(entry.tid)
            more=KERNEL.Thread32Next(snapshot,ctypes.byref(entry))
    finally:KERNEL.CloseHandle(snapshot)
    return ids


def batch(c, args):
    result = tool(c, "veh_batch", {"steps":[{"tool":"veh_threads","args":args}]})
    return result["results"][0]["result"]


def check_actions():
    with OwnedMcpClient() as c:
        c.initialize("thread-actions")
        pid, main, bits, data, code = setup(c)
        terminal = program(c, main, bits, data, code, [(0, 61)])
        worker = start_worker(c, bits, code)
        listed = tool(c, "veh_threads")
        assert listed == tool(c, "veh_threads", {"action":"list"}) == batch(c, {})
        hidden=set(native_threads(pid))-{row["id"] for row in listed["threads"]}
        assert hidden, "expected protected debugger threads"
        for tid in hidden:
            assert "error" in c.tool("veh_threads",{"action":"terminate","threadId":tid})
        for args in [
            {"action":"bad"}, {"action":None}, {"action":"terminate"},
            {"action":"terminate","threadId":0}, {"action":"terminate","threadId":-1},
            {"action":"terminate","threadId":2**32+worker}, {"action":"freeze","threadId":1.5},
            {"action":"terminate","threadId":str(worker)}, {"action":"freeze"},
        ]:
            direct = c.tool("veh_threads", args)
            assert "error" in direct and batch(c,args) == direct, (args,direct)
        frozen = tool(c,"veh_threads",{"action":"freeze","threadId":worker})
        assert frozen == tool(c,"veh_freeze_thread",{"threadId":worker})
        assert batch(c,{"action":"thaw","threadId":0})["frozenThreads"] == []
        assert batch(c,{"action":"freeze","threadId":worker}) == frozen
        assert tool(c,"veh_freeze_thread",{"threadId":worker,"frozen":False})["frozenThreads"] == []
        # A real foreign thread must never be terminated by the in-target command.
        foreign = c.tool("veh_threads",{"action":"terminate","threadId":KERNEL.GetCurrentThreadId()})
        assert "error" in foreign, foreign
        assert "error" in c.tool("veh_threads",{"action":"freeze","threadId":KERNEL.GetCurrentThreadId()})
        # Park the worker at an actual software breakpoint, then terminate it frozen.
        hit = tool(c,"veh_continue",{"threadId":worker,"wait":True,"timeout":4})
        assert hit["breakpointId"] == terminal["id"], hit
        tool(c,"veh_threads",{"action":"freeze","threadId":worker})
        killed = batch(c,{"action":"terminate","threadId":worker})
        assert killed == {"success":True,"action":"terminate","threadId":worker,"terminated":True}, killed
        assert worker not in [t["id"] for t in tool(c,"veh_threads")["threads"]]
        assert worker not in tool(c,"veh_threads",{"action":"thaw","threadId":0})["frozenThreads"]
        end = tool(c,"veh_continue",{"threadId":main,"wait":True,"timeout":4})
        assert end["threadId"] == main and end["breakpointId"] == terminal["id"], end
        assert "error" in c.tool("veh_threads",{"action":"terminate","threadId":worker})
    print("PASS thread actions default/list, legacy parity, direct/batch controls, strict IDs and stopped/frozen termination")


def check_running_termination():
    import struct
    with OwnedMcpClient() as c:
        c.initialize("thread-running-termination")
        pid, main, bits, data, code = setup(c)
        terminal=program(c,main,bits,data,code,[(0,64)])
        tool(c,"veh_remove_breakpoint",{"id":terminal["id"]})
        end=int(terminal["address"],0)
        tool(c,"veh_write_memory",{"address":hex(end),"data":(bytes([0xE9])+struct.pack("<i",code-(end+5))).hex()})
        worker=start_worker(c,bits,code)
        assert tool(c,"veh_threads",{"action":"terminate","threadId":worker})["terminated"]
        assert main in [t["id"] for t in tool(c,"veh_threads")["threads"]]
    print("PASS forceful termination of a running worker preserves the target session")


def check_page_cleanup():
    with OwnedMcpClient() as c:
        c.initialize("thread-page-cleanup")
        pid, main, bits, data, code = setup(c)
        terminal = program(c, main, bits, data, code, [(0,62)])
        entry = tool(c,"veh_set_breakpoint",{"address":hex(code)})
        worker = start_worker(c,bits,code)
        assert tool(c,"veh_continue",{"threadId":worker,"wait":True,"timeout":4})["breakpointId"] == entry["id"]
        tool(c,"veh_remove_breakpoint",{"id":entry["id"]})
        watch = tool(c,"veh_set_data_breakpoint",{"address":hex(data),"method":"page"})
        hit = tool(c,"veh_continue",{"threadId":worker,"wait":True,"timeout":4})
        assert hit["breakpointId"] == watch["id"], hit
        assert tool(c,"veh_threads",{"action":"terminate","threadId":worker})["terminated"]
        assert protect(pid,data)&0x100
        hit = tool(c,"veh_continue",{"threadId":main,"wait":True,"timeout":4})
        assert hit["threadId"] == main and hit["breakpointId"] == watch["id"], hit
        tool(c,"veh_remove_data_breakpoint",{"id":watch["id"]})
        assert tool(c,"veh_continue",{"threadId":main,"wait":True,"timeout":4})["breakpointId"] == terminal["id"]
    print("PASS terminated page-stop lease is cleaned without losing peer page coverage")


def check_action_parity():
    with tempfile.TemporaryDirectory(prefix="veh-thread-actions-") as directory, OwnedMcpClient(args=["--log="+str(Path(directory)/"mcp.log")]) as c:
        c.initialize("thread-breakpoint-actions")
        pid, main, bits, data, code = setup(c)
        terminal = program(c,main,bits,data,code,[(0,63)])
        worker = start_worker(c,bits,code)
        assert tool(c,"veh_continue",{"threadId":worker,"wait":True,"timeout":4})["breakpointId"] == terminal["id"]
        address = code+(10 if bits==64 else 5)
        bp = tool(c,"veh_set_breakpoint",{"address":hex(address),"action":[
            {"tool":"veh_threads","args":{"action":"freeze","threadId":worker}},
            {"tool":"veh_threads","args":{"action":"thaw","threadId":worker}},
            {"tool":"veh_threads","args":{"action":"terminate","threadId":worker}},
        ]})
        end = tool(c,"veh_continue",{"threadId":main,"wait":True,"timeout":4})
        assert end["threadId"] == main and end["breakpointId"] == terminal["id"], end
        rows = tool(c,"veh_threads")["threads"]
        assert any(t["id"]==worker and not t.get("frozen") for t in rows)
        assert "termination is unavailable in breakpoint actions" in (Path(directory)/"mcp.log").read_text(encoding="utf-8",errors="replace")
        tool(c,"veh_remove_breakpoint",{"id":bp["id"]})
    print("PASS freeze/thaw breakpoint actions and explicit termination exclusion")


def check_peers():
    for mode in ["control-ok","control-error","control-short","control-long","reply-empty"]:
        with OwnedMcpClient() as c:
            c.initialize("thread-control-peer")
            tool(c,"veh_attach",{"pid":4242,"target_scope":"guest","agent":AGENT,
                                "agent_args":["--metadata",mode]})
            args={"action":"terminate","threadId":77}
            result=c.tool("veh_threads",args)
            if mode=="control-ok":assert result.get("terminated"),result
            else:
                assert "error" in result and not result.get("terminated"),(mode,result)
                assert batch(c,args)==result,(mode,result)
                if mode=="reply-empty":assert "unsupported" in result["error"].lower(),result
    print("PASS backend capability refusal, execution errors and exact termination reply validation")


if __name__=="__main__":
    check_actions()
    check_running_termination()
    check_page_cleanup()
    check_action_parity()
    check_peers()
