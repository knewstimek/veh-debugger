"""DAP next/step-over integration test with bounded I/O and cleanup."""
import os
from build_paths import RELEASE

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
        thread_id = hit["body"]["threadId"]
        stack = client.request("stackTrace", {"threadId": thread_id, "startFrame": 0, "levels": 1})
        before = stack["body"]["stackFrames"][0]["instructionPointerReference"]
        observed = []
        for _ in range(3):
            response = client.request("next", {"threadId": thread_id})
            assert response.get("success"), response
            stopped = client.event("stopped", 15)
            thread_id = stopped["body"]["threadId"]
            stack = client.request("stackTrace", {"threadId": thread_id, "startFrame": 0, "levels": 1})
            observed.append(stack["body"]["stackFrames"][0]["instructionPointerReference"])
        assert any(address != before for address in observed), (before, observed)
        print(f"PASS: DAP next changed instruction pointer across {len(observed)} bounded steps")
    finally:
        client.close()


if __name__ == "__main__":
    main()
