"""DAP memory and disassembly must mask a software-breakpoint INT3."""
import base64
from build_paths import RELEASE
import os

from dap_test_client import DapClient


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ADAPTER = os.path.join(RELEASE, "veh-debug-adapter.exe")
TARGET = os.path.join(RELEASE, "test_target.exe")
SOURCE = os.path.join(ROOT, "test_target", "main.cpp")


def main():
    with open(SOURCE, encoding="utf-8") as source:
        breakpoint_line = next(index for index, line in enumerate(source, 1)
                               if 'printf("[%d] Working' in line)
    client = DapClient(ADAPTER)
    try:
        client.initialize()
        launch_seq = client.send("launch", {"program": TARGET, "stopOnEntry": True})
        launch = client.wait_for(lambda item: item.get("request_seq") == launch_seq, 15)
        assert launch.get("success"), launch
        client.event("initialized", 10)
        breakpoint = client.request("setBreakpoints", {
            "source": {"path": SOURCE}, "breakpoints": [{"line": breakpoint_line}],
        })
        assert breakpoint.get("success") and breakpoint["body"]["breakpoints"][0]["verified"], breakpoint
        client.request("configurationDone")
        entry = client.event("stopped", 10)
        client.request("continue", {"threadId": entry["body"]["threadId"]})
        hit = client.event("stopped", 15, lambda item: item["body"].get("reason") == "breakpoint")
        stack = client.request("stackTrace", {
            "threadId": hit["body"]["threadId"], "startFrame": 0, "levels": 1,
        })
        address = stack["body"]["stackFrames"][0]["instructionPointerReference"]
        memory = client.request("readMemory", {"memoryReference": address, "count": 16})
        data = base64.b64decode(memory["body"]["data"])
        assert data and data[0] != 0xCC, data.hex()
        disassembly = client.request("disassemble", {
            "memoryReference": address, "instructionCount": 3, "offset": 0,
        })
        instructions = disassembly["body"]["instructions"]
        assert instructions and "int3" not in instructions[0].get("instruction", "").lower(), instructions
        print(f"PASS: breakpoint byte masked as {data[0]:02X} in memory and disassembly")
    finally:
        client.close()


if __name__ == "__main__":
    main()
