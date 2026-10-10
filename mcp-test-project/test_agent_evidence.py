"""Oracle tests are synthetic evidence tests, never real Agent tests."""
import json
from pathlib import Path
import tempfile
import subprocess
import sys
import unittest

from agent_evidence import assess, digest
from client_proxy import Evidence
from mock_ida import A, B, BUSY, TIMEOUT, SLOW
from run_agent_clients import configuration
from verify_stdio import EXPECTED_TOOLS


def observed_run():
    events = [{"direction": "response", "method": "tools/list", "connection": "one", "time": 0,
        "tools": [{"name": name, "inputSchema": {"type": "object"}} for name in EXPECTED_TOOLS]}]
    def response(tool, at, **fields):
        events.append({"direction": "response", "method": "tools/call", "tool": tool,
                       "connection": "one", "time": at, "isError": False,
                       "textMatchesStructured": True, **fields})
    for name in EXPECTED_TOOLS:
        response(name, 1)
    response("ida_list_instances", 1, instanceIds=[A, B])
    response("ida_select_instance", 1, arguments={"instanceId": A})
    response("ida_read_memory", 2, isError=True, code="INVALID_ARGUMENT", hasHint=True,
             issues=[{"field": "arguments", "rule": "oneOf"}])
    response("ida_read_memory", 3)
    for at, args, marker in ((4, {}, "SIMULATED-A.i64"), (5, {"instanceId": B}, "SIMULATED-B.i64"),
                             (6, {}, "SIMULATED-A.i64")):
        response("ida_database_info", at, arguments=args, databaseSha256=digest(marker))
    response("ida_get_function", 7, arguments={"address": BUSY})
    response("ida_get_function", 8, arguments={"address": TIMEOUT}, isError=True, code="TIMEOUT")
    response("ida_get_function", 9, arguments={"address": "0x401000"})
    for i in range(6):
        events.append({"direction": "request", "method": "tools/call", "tool": "ida_get_function",
                       "connection": "one", "time": 10, "id": i, "arguments": {"address": SLOW, "instanceId": A}})
    for i in range(6):
        response("ida_get_function", 11, id=i, arguments={"address": SLOW, "instanceId": A}, durationMs=2400)
    rpc = [{"phase": "start", "method": "function.get", "address": BUSY, "instance": A} for _ in range(3)]
    rpc += [{"phase": "start", "address": SLOW, "active": 2, "instance": A} for _ in range(6)]
    return events, rpc


class AgentEvidenceTests(unittest.TestCase):
    def test_complete_observed_run(self):
        events, rpc = observed_run()
        result = assess(events, rpc_events=rpc)
        self.assertNotIn("failed", result.values())
        self.assertEqual(result["concurrent_queue"], "passed")
        self.assertEqual(result["agent_request_deadline"], "not_observed")

    def test_no_calls_or_model_prose_cannot_pass(self):
        result = assess([])
        self.assertEqual(result["all_23_tool_calls"], "failed")
        self.assertEqual(result["discovery_and_23_schemas"], "failed")

    def test_missing_schema_and_tool_calls_fail(self):
        events, rpc = observed_run()
        events[0]["tools"].pop()
        events = [e for e in events if e.get("tool") != "ida_types"]
        result = assess(events, rpc_events=rpc)
        self.assertEqual(result["all_23_tool_calls"], "failed")
        self.assertEqual(result["discovery_and_23_schemas"], "failed")

    def test_invalid_schema_fails(self):
        events, _ = observed_run()
        events[0]["tools"][0]["inputSchema"] = {"type": "invalid-type"}
        self.assertEqual(assess(events)["discovery_and_23_schemas"], "failed")

    def test_protocol_error_is_not_a_successful_call(self):
        events, _ = observed_run()
        for e in events:
            if e.get("tool") == "ida_types":
                e["protocolError"] = -32602
        self.assertEqual(assess(events)["all_23_tool_calls"], "failed")

    def test_wrong_database_and_cross_session_recovery_fail(self):
        events, rpc = observed_run()
        for e in events:
            if e.get("databaseSha256") == digest("SIMULATED-B.i64"):
                e["databaseSha256"] = digest("SIMULATED-A.i64")
            if e.get("code") == "INVALID_ARGUMENT":
                e["connection"] = "different-gateway"
        result = assess(events, rpc_events=rpc)
        self.assertEqual(result["selected_a_explicit_b_selected_a"], "failed")
        self.assertEqual(result["structured_error_recovery"], "failed")

    def test_serial_calls_do_not_prove_queue_support(self):
        events, rpc = observed_run()
        events = [e for e in events if e.get("direction") != "request"]
        self.assertEqual(assess(events, rpc_events=rpc)["concurrent_queue"], "not_observed")

    def test_proxy_correlates_responses_and_hides_result_body(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "wire.jsonl"
            evidence = Evidence(path)
            evidence.record("request", {"id": 5, "method": "tools/call", "params": {
                "name": "ida_database_info", "arguments": {"instanceId": A, "code": "SECRET"}}})
            body = {"database": "PRIVATE-DB.i64"}
            evidence.record("response", {"id": 5, "result": {"content": [{"type": "text",
                "text": json.dumps(body)}], "structuredContent": body}})
            record = json.loads(path.read_text().splitlines()[-1])
            self.assertEqual(record["tool"], "ida_database_info")
            self.assertEqual(record["arguments"], {"instanceId": A})
            self.assertTrue(record["textMatchesStructured"])
            self.assertEqual(record["databaseSha256"], digest("PRIVATE-DB.i64"))
            self.assertNotIn("SECRET", path.read_text())
            self.assertNotIn("PRIVATE-DB", path.read_text())

    def test_client_configs_keep_paths_as_argv(self):
        with tempfile.TemporaryDirectory(prefix="agent path ") as directory:
            for client in ("codex", "claude", "opencode"):
                args, env = configuration(client, ["python path", "proxy path", "--", "gateway path"],
                                           Path(directory), "pinned-model")
                self.assertIn("pinned-model", args)
                if client == "codex":
                    self.assertIn("--ignore-user-config", args)
                elif client == "claude":
                    self.assertIn("--strict-mcp-config", args)
                else:
                    self.assertIn("--standalone", args)
                    config = json.loads(Path(env["OPENCODE_CONFIG"]).read_text())
                    entry = config["mcp"]["servers"]["ida_regression"]
                    self.assertEqual(entry["command"], ["python path", "proxy path", "--", "gateway path"])
                    self.assertFalse(entry["disabled"])
                    self.assertFalse(entry["codemode"])
                    self.assertEqual(entry["protocol"], "legacy")
                    self.assertEqual(entry["timeout"], {"catalog": 20000, "execution": 20000})
                    self.assertEqual(config["permissions"], [
                        {"action": "*", "resource": "*", "effect": "deny"},
                        {"action": "ida_regression_*", "resource": "*", "effect": "allow"}])

    def test_proxy_forwards_invalid_json_and_non_object_messages_unchanged(self):
        # A byte-echo subprocess, not an MCP server or an Agent.
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "wire.jsonl"
            proxy = Path(__file__).with_name("client_proxy.py")
            data = b'invalid json\n[]\n{"id":1,"method":"tools/list"}\n'
            result = subprocess.run([sys.executable, str(proxy), "--evidence", str(path), "--",
                sys.executable, "-c", "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())"],
                input=data, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, data)


if __name__ == "__main__":
    unittest.main()
