"""DAP stepIn integration test with bounded I/O and cleanup."""
import os
from build_paths import RELEASE

from dap_test_client import DapClient


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ADAPTER = os.path.join(RELEASE, "veh-debug-adapter.exe")
TARGET = os.path.join(RELEASE, "test_target.exe")
SOURCE = os.path.join(ROOT, "test_target", "main.cpp")


def main():
    with open(SOURCE, encoding="utf-8") as source:
        call_line = next(index for index, line in enumerate(source, 1)
                         if line.strip() == "WorkFunction();")
    client = DapClient(ADAPTER)
    try:
        client.initialize()
        launch_seq = client.send("launch", {"program": TARGET, "stopOnEntry": True})
        launch = client.wait_for(lambda item: item.get("request_seq") == launch_seq, 15)
        assert launch.get("success"), launch
        client.event("initialized", 10)
        breakpoint = client.request("setBreakpoints", {
            "source": {"path": SOURCE}, "breakpoints": [{"line": call_line}],
        })
        assert breakpoint.get("success") and breakpoint["body"]["breakpoints"][0]["verified"], breakpoint
        client.request("configurationDone")
        entry = client.event("stopped", 10)
        client.request("continue", {"threadId": entry["body"]["threadId"]})
        hit = client.event("stopped", 15, lambda item: item["body"].get("reason") == "breakpoint")
        thread_id = hit["body"]["threadId"]
        frames = []
        for _ in range(6):
            response = client.request("stepIn", {"threadId": thread_id})
            assert response.get("success"), response
            stopped = client.event("stopped", 15)
            thread_id = stopped["body"]["threadId"]
            stack = client.request("stackTrace", {
                "threadId": thread_id, "startFrame": 0, "levels": 3,
            })
            frames = stack["body"]["stackFrames"]
            if frames and "WorkFunction" in frames[0].get("name", ""):
                break
        assert frames and "WorkFunction" in frames[0].get("name", ""), frames
        print(f"PASS: DAP stepIn entered {frames[0]['name']}")
    finally:
        client.close()


if __name__ == "__main__":
    main()
