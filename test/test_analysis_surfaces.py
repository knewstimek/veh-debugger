"""Bounded exact-address annotations in stop replies, stacks and breakpoint lists."""
from test_analysis import analysis, native, environment, BIN
from owned_mcp_client import OwnedMcpClient


def test_stop_stack_breakpoint_labels_and_opt_out(tmp_path):
    with native(tmp_path) as (client, address):
        saved = analysis(client, "set", address=address, label="work_entry", comment="request processing entry")
        assert saved.get("success"), saved
        installed = client.tool("veh_set_breakpoint", {"address": address})
        assert installed.get("success"), installed
        listed = client.tool("veh_list_breakpoints")
        entry = next(row for row in listed["software"] if row["id"] == installed["id"])
        assert entry["annotation"] == {"label": "work_entry", "code_validation": "not_checked"}, entry
        plain = client.tool("veh_list_breakpoints", {"include_annotations": False})
        assert all("annotation" not in row for row in plain["software"]), plain
        stop = client.tool("veh_continue", {"wait": True, "timeout": 5}, timeout=7)
        assert stop.get("stopped") and stop["annotation"]["label"] == "work_entry", stop
        assert stop["annotation"]["comment"] == "request processing entry" and not stop["annotation"]["stale"], stop
        stack = client.tool("veh_stack_trace", {"threadId": stop["threadId"]})
        assert stack["frames"], stack
        exact = [row for row in stack["frames"] if int(row["address"], 16) == int(address, 16)]
        assert exact and exact[0]["annotation"]["label"] == "work_entry", stack
        for frame in stack["frames"]:
            if int(frame["address"], 16) != int(address, 16): assert "annotation" not in frame, frame
            if "annotation" in frame: assert "comment" not in frame["annotation"], frame
        no_notes = client.tool("veh_stack_trace", {"threadId": stop["threadId"], "include_annotations": False})
        assert all("annotation" not in row for row in no_notes["frames"]), no_notes
        batch = client.tool("veh_batch", {"steps": [
            {"tool": "veh_list_breakpoints"}, {"tool": "veh_stack_trace", "args": {"threadId": stop["threadId"]}}]})
        assert batch["results"][0]["result"] == client.tool("veh_list_breakpoints"), batch
        assert batch["results"][1]["result"] == stack, batch
        # A label at the next instruction must be selected from the completed step IP.
        instructions = client.tool("veh_disassemble", {"address": address, "count": 4})["instructions"]
        labels = {}
        for index, instruction in enumerate(instructions[1:], 1):
            label = "step_destination_" + str(index)
            assert analysis(client, "set", address=instruction["address"], label=label, comment="instruction-specific step destination")["success"]
            labels[int(instruction["address"], 16)] = label
        step = client.tool("veh_step_in", {"threadId": stop["threadId"]})
        assert step.get("success") and int(step["instructionPointer"], 16) in labels, step
        assert step["annotation"]["label"] == labels[int(step["instructionPointer"], 16)], step
        stopped = client.tool("veh_continue", {"wait": True, "timeout": 5, "include_annotations": False}, timeout=7)
        assert stopped.get("stopped") and "annotation" not in stopped, stopped


def test_comment_only_and_pending_breakpoints_do_not_expand_lists(tmp_path):
    with native(tmp_path) as (client, address):
        assert analysis(client, "set", address=address, comment="not a label")["success"]
        assert client.tool("veh_set_breakpoint", {"address": address})["success"]
        pending = client.tool("veh_set_function_breakpoint", {"name": "not_loaded_fixture.dll!FutureEntry"})
        assert pending.get("pending"), pending
        listed = client.tool("veh_list_breakpoints")
        assert all("annotation" not in row for row in listed["software"]), listed
        assert any(row["status"] == "pending" for row in listed["software"]), listed


def test_hardware_and_action_listing_share_label_semantics(tmp_path):
    logfile = tmp_path / "surface-actions.log"
    with native(tmp_path, client_args=["--log=" + str(logfile)]) as (client, address):
        assert analysis(client, "set", address=address, label="work_entry", comment="not repeated in a list")["success"]
        hardware = client.tool("veh_set_data_breakpoint", {"address": address, "type": "execute", "size": 1})
        assert hardware.get("success"), hardware
        listing = client.tool("veh_list_breakpoints")
        entry = next(row for row in listing["hardware"] if row["id"] == hardware["id"])
        assert entry["annotation"] == {"label": "work_entry", "code_validation": "not_checked"}, listing
        assert client.tool("veh_remove_data_breakpoint", {"id": hardware["id"]})["success"]
        # Actions run on the command worker, not the pipe event callback thread.
        installed = client.tool("veh_set_breakpoint", {"address": address, "action": [
            {"tool": "veh_list_breakpoints", "args": {}}]})
        assert installed.get("success"), installed
        stop = client.tool("veh_continue", {"wait": True, "timeout": 1}, timeout=4)
        assert stop.get("timeout"), stop  # breakpoint actions automatically continue
        # Stop notes are omitted if the action already resumed the thread.
        after = client.tool("veh_list_breakpoints")
        assert any(row.get("hitCount", 0) > 0 for row in after["software"]), after
        assert client.tool("veh_remove_breakpoint", {"id": installed["id"]})["success"]
    assert "Breakpoint action completed with an error:" not in logfile.read_text(encoding="utf-8")


def test_large_stack_reports_annotation_budget_without_repeating_comments(tmp_path):
    with OwnedMcpClient(env=environment(tmp_path)) as client:
        client.initialize()
        assert client.tool("veh_attach", {"pid": 424242, "agent": str(BIN / "guest_backend_fixture.exe"),
            "target_scope": "guest", "agent_args": ["--metadata", "symbols-analysis-stack-many"]})["success"]
        assert analysis(client, "open", directory=str(tmp_path / "project"), create=True)["success"]
        assert analysis(client, "set", address="0x1100", label="recursive_site", comment="never repeat this body in frames")["success"]
        result = client.tool("veh_stack_trace", {"threadId": 77, "maxFrames": 25})
        assert result["count"] == 25 and result["annotations_truncated"], result
        assert sum("annotation" in row for row in result["frames"]) == 20, result
        assert all("comment" not in row.get("annotation", {}) for row in result["frames"]), result
