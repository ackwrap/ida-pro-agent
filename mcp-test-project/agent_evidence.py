"""Fail-closed Agent assertions: wire events and fixture traces, not final prose."""
import hashlib
import json

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError
from mock_ida import A, B, BUSY, TIMEOUT, SLOW
from verify_stdio import EXPECTED_TOOLS


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def read_events(path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def assess(events, simulated=True, rpc_events=(), instance_a=A, instance_b=B,
           database_a="SIMULATED-A.i64", database_b="SIMULATED-B.i64"):
    checks = {}
    catalogs = [e for e in events if e.get("method") == "tools/list" and e["direction"] == "response"]
    try:
        assert catalogs, "No tools/list response observed"
        for entry in catalogs:
            tools = entry.get("tools", [])
            assert len(tools) == 23 and {t["name"] for t in tools} == EXPECTED_TOOLS
            for tool in tools:
                Draft202012Validator.check_schema(tool["inputSchema"])
        checks["discovery_and_23_schemas"] = "passed"
    except (AssertionError, ValueError, SchemaError) as error:
        checks["discovery_and_23_schemas"] = "failed"
        checks["catalog_reason"] = str(error)
    responses = [e for e in events if e.get("method") == "tools/call" and e["direction"] == "response"]
    success = [e for e in responses if not e.get("isError") and "protocolError" not in e]
    used = {e.get("tool") for e in success}
    checks["all_23_tool_calls"] = "passed" if EXPECTED_TOOLS <= used else "failed"
    checks["missing_tool_calls"] = sorted(EXPECTED_TOOLS - used)
    checks["text_structured_consistency"] = "passed" if responses and all(
        e.get("textMatchesStructured") for e in responses) else "failed"
    # Match recovery within the same gateway connection, after its error response.
    errors = [e for e in responses if e.get("isError") and e.get("code") == "INVALID_ARGUMENT" and
              e.get("tool") == "ida_read_memory" and e.get("hasHint") and e.get("issues")]
    checks["structured_error_recovery"] = "passed" if any(
        ok["tool"] == "ida_read_memory" and ok["connection"] == bad["connection"] and
        ok["time"] > bad["time"] for bad in errors for ok in success) else "failed"
    db = [e for e in success if e.get("tool") == "ida_database_info"]
    expected = (digest(database_a), digest(database_b), digest(database_a))
    discovered = any({instance_a, instance_b} <= set(e.get("instanceIds", []))
                     for e in success if e.get("tool") == "ida_list_instances")
    route_ok = False
    for i in range(len(db) - 2):
        triple = db[i:i+3]
        if len({e["connection"] for e in triple}) != 1:
            continue
        selected = any(e.get("tool") == "ida_select_instance" and
                       e.get("arguments", {}).get("instanceId") == instance_a and
                       e["connection"] == triple[0]["connection"] and e["time"] < triple[0]["time"]
                       for e in success)
        if selected and discovered and tuple(e.get("databaseSha256") for e in triple) == expected and \
                "instanceId" not in triple[0].get("arguments", {}) and \
                triple[1].get("arguments", {}).get("instanceId") == instance_b and \
                "instanceId" not in triple[2].get("arguments", {}):
            route_ok = True
    checks["selected_a_explicit_b_selected_a"] = "passed" if route_ok else "failed"
    if not simulated:
        checks["busy_retries"] = checks["timeout_recovery"] = checks["concurrent_queue"] = "not_observed"
        return checks
    attempts = [e for e in rpc_events if e.get("phase") == "start" and
                e.get("method") == "function.get" and e.get("address") == BUSY and
                e.get("instance") == instance_a]
    checks["busy_retries"] = "passed" if len(attempts) == 3 and any(
        e.get("arguments", {}).get("address") == BUSY for e in success) else "failed"
    timeouts = [e for e in responses if e.get("isError") and e.get("code") == "TIMEOUT" and
                e.get("arguments", {}).get("address") == TIMEOUT]
    checks["timeout_recovery"] = "passed" if any(ok["connection"] == bad["connection"] and
        ok["time"] > bad["time"] for bad in timeouts for ok in success) else "failed"
    pending, maximum = {}, 0
    for event in events:
        if event.get("method") != "tools/call" or event.get("arguments", {}).get("address") != SLOW or \
                event.get("arguments", {}).get("instanceId") != instance_a:
            continue
        key = (event["connection"], event.get("id"))
        if event["direction"] == "request":
            pending[key] = True
            maximum = max(maximum, sum(k[0] == event["connection"] for k in pending))
        else:
            pending.pop(key, None)
    starts = [e for e in rpc_events if e.get("phase") == "start" and e.get("address") == SLOW and
              e.get("instance") == instance_a]
    completed = [e for e in success if e.get("arguments", {}).get("address") == SLOW and
                 e.get("arguments", {}).get("instanceId") == instance_a]
    checks["max_outstanding_slow_calls"] = maximum
    checks["concurrent_queue"] = "passed" if maximum >= 6 and len(completed) >= 6 and starts and \
        max(e["active"] for e in starts) == 2 and max(e.get("durationMs", 0) for e in completed) >= 1200 \
        else "not_observed"
    # Agent recovery from a tool-level TIMEOUT is separate from its own deadline policy.
    checks["agent_request_deadline"] = "not_observed"
    return checks
