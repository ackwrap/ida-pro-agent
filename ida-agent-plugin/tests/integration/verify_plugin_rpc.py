import argparse
import base64
import json
import re
import sys

from plugin_rpc_client import (
    RpcVerifier,
    load_json,
    matching_item,
    require,
    require_address,
    require_keys,
    require_page,
)

EXPECTED_METHODS = {
    "analysis.component",
    "analysis.diff_before_after",
    "analysis.problems",
    "analysis.plan",
    "analysis.status",
    "analysis.trace_data_flow",
    "analysis.trace_argument",
    "analysis.trace_argument_callers",
    "analysis.guard_evidence",
    "bookmark.list",
    "changeset.apply",
    "changeset.audit",
    "changeset.preview",
    "changeset.rollback",
    "database.entry_points",
    "database.info",
    "database.save",
    "database.segments",
    "database.survey",
    "comment.get",
    "debugger.breakpoints",
    "debugger.control",
    "debugger.exit",
    "debugger.backends",
    "debugger.configuration",
    "debugger.processes",
    "debugger.select",
    "debugger.configure",
    "debugger.attach",
    "debugger.detach",
    "debugger.suspend",
    "debugger.info",
    "debugger.memory_read",
    "debugger.memory_write",
    "debugger.registers",
    "debugger.stacktrace",
    "debugger.start",
    "debugger.threads",
    "debugger.modules",
    "decompiler.locals",
    "decompiler.ctree",
    "decompiler.local_xrefs",
    "exception.try_blocks",
    "fixup.get",
    "fixup.list",
    "function.analyze",
    "function.analyze_batch",
    "function.basic_blocks",
    "function.callees",
    "function.callers",
    "function.callgraph",
    "function.chunks",
    "function.decompile",
    "function.disassemble",
    "function.export",
    "function.get",
    "function.profile",
    "function.search",
    "function.stack_frame",
    "global.value",
    "instruction.query",
    "instruction.search",
    "instruction.get",
    "listing.search",
    "listing.search_text",
    "memory.read",
    "memory.search_bytes",
    "name.demangle",
    "patch.assemble",
    "signature.make",
    "signature.xrefs",
    "script.execute",
    "string.search",
    "string.search_regex",
    "symbol.exports",
    "symbol.imports",
    "symbol.search",
    "switch.get",
    "source.files",
    "source.lines",
    "system.methods",
    "type.get",
    "type.infer",
    "type.query",
    "type.read_struct",
    "type.read_value",
    "type.search",
    "type.xrefs",
    "xref.query",
    "xref.struct_field",
}


def verify_methods(rpc):
    methods = rpc.call("system.methods", {})
    require_keys(methods, {"methods"}, "system.methods result", exact=True)
    require(methods["methods"] == sorted(EXPECTED_METHODS),
            "system.methods mismatch; missing=%s unexpected=%s" % (
                sorted(EXPECTED_METHODS - set(methods["methods"])),
                sorted(set(methods["methods"]) - EXPECTED_METHODS)))


def verify_identity(rpc):
    ping = rpc.call("system.ping", {})
    require(ping == {"status": "ok"}, "system.ping result mismatch")
    info = rpc.call("instance.info", {})
    require_keys(info, {"instance_id", "pid", "ida_version", "database", "input_file",
                        "processor", "bitness", "architecture", "capabilities"},
                 "instance.info result", exact=True)
    require(info["instance_id"] == rpc.instance_id and info["pid"] == rpc.pid,
            "instance.info identity mismatch")


def verify_scripts(rpc):
    rpc.call_error("script.execute", {
        "language": "python", "code": "print('blocked')", "confirmed": True},
        {"INVALID_ARGUMENT"})
    python = rpc.call("script.execute", {
        "language": "python", "code": "print('ida-agent-script-ok')"})
    require(python == {
        "language": "python", "success": True, "result": None,
        "stdout": "ida-agent-script-ok\n", "stderr": "", "truncated": False,
        "originalSize": len("ida-agent-script-ok\n")},
        "script.execute Python result mismatch")
    idc = rpc.call("script.execute", {"language": "idc", "code": "return 1 + 1;"})
    require(idc["language"] == "idc" and idc["success"] and idc["result"] is not None,
            "script.execute IDC result mismatch")


def verify_database(rpc, fixture):
    result = rpc.call("database.info", {})
    require_keys(result, {"database", "processor", "architecture", "addressBits",
                          "addressRange", "segments"}, "database.info result", exact=True)
    require(result["segments"]["total"] > 0, "database.info reported no segments")
    segments = rpc.call("database.segments", {"limit": 10})
    require_page(segments, "database.segments result")
    require(segments["items"], "database.segments returned no items")
    require_keys(segments["items"][0], {"start", "end", "name", "class", "bitness",
                                        "permissions", "type"}, "database.segments item", exact=True)
    entries = rpc.call("database.entry_points", {"limit": 10})
    require_page(entries, "database.entry_points result")
    for item in entries["items"]:
        require_keys(item, {"address", "name", "type"}, "database.entry_points item")
        require_address(item["address"], "database.entry_points item.address")
    survey = rpc.call("database.survey", {"mode": "minimal", "budget": 6})
    require_keys(survey, {"mode", "metadata", "statistics", "importCategories", "callGraph",
                          "metrics", "truncated", "budget", "functions", "strings"},
                 "database.survey result", exact=True)
    require(survey["mode"] == "minimal", "database.survey mode mismatch")
    saved = rpc.call("database.save", {"compact": False, "backup": False})
    require(saved == {"saved": True, "explicitTarget": False}, "database.save result mismatch")
    rpc.call_error("database.save", {"target": "forbidden.i64"}, {"INVALID_ARGUMENT"})


def verify_functions(rpc, fixture):
    caller = fixture["functionAddress"]
    target = fixture["callTarget"]
    site = fixture["callSite"]
    function = rpc.call("function.get", {"address": caller})
    require_keys(function, {"entryAddress", "addressRange", "name", "signature", "flags", "statistics"},
                 "function.get result", exact=True)
    require(function["entryAddress"] == caller, "function.get entryAddress mismatch")
    require(function["addressRange"]["end"] == fixture["functionEnd"], "function.get end mismatch")
    require(function["name"] == fixture["functionName"], "function.get name mismatch")
    search = rpc.call("function.search", {"address": caller, "limit": 10})
    require_page(search, "function.search result")
    require(matching_item(search["items"], "entryAddress", caller) is not None,
            "function.search did not return the fixture function")
    disassembly = rpc.call("function.disassemble", {"address": caller, "limit": 100})
    require_keys(disassembly, {"entryAddress", "items", "nextOffset", "hasMore"},
                 "function.disassemble result", exact=True)
    require(disassembly["entryAddress"] == caller and disassembly["items"],
            "function.disassemble did not return fixture instructions")
    blocks = rpc.call("function.basic_blocks", {"address": caller, "limit": 100})
    require_keys(blocks, {"entryAddress", "items", "nextOffset", "hasMore"},
                 "function.basic_blocks result", exact=True)
    require(blocks["entryAddress"] == caller and blocks["items"],
            "function.basic_blocks did not return fixture blocks")
    chunks = rpc.call("function.chunks", {"address": caller, "limit": 100})
    require_keys(chunks, {"entryAddress", "items", "nextOffset", "hasMore"},
                 "function.chunks result", exact=True)
    require(chunks["entryAddress"] == caller and chunks["items"],
            "function.chunks did not return fixture chunks")
    try_blocks = rpc.call("exception.try_blocks", {"address": caller, "limit": 100})
    require_keys(try_blocks, {"functionAddress", "items", "truncated"},
                 "exception.try_blocks result", exact=True)
    require(try_blocks["functionAddress"] == caller,
            "exception.try_blocks function address mismatch")
    callees = rpc.call("function.callees", {"address": caller, "limit": 100})
    require_keys(callees, {"entryAddress", "items", "nextOffset", "hasMore"},
                 "function.callees result", exact=True)
    require(matching_item(callees["items"], "address", target) is not None,
            "function.callees did not contain the fixture target")
    callers = rpc.call("function.callers", {"address": target, "limit": 100})
    require_keys(callers, {"entryAddress", "items", "nextOffset", "hasMore"},
                 "function.callers result", exact=True)
    caller_item = matching_item(callers["items"], "address", caller)
    require(caller_item is not None and site in caller_item.get("callSites", []),
            "function.callers did not preserve caller/target/site relationship")
    graph = rpc.call("function.callgraph", {"roots": [caller], "direction": "callees",
                                             "maxDepth": 1, "maxNodes": 100, "maxEdges": 100})
    require_keys(graph, {"nodes", "edges", "truncated"}, "function.callgraph result", exact=True)
    require(any(edge.get("from") == caller and edge.get("to") == target for edge in graph["edges"]),
            "function.callgraph did not contain the fixture edge")
    code = rpc.call("function.decompile", {"address": caller, "maxBytes": 65536})
    require_keys(code, {"entryAddress", "pseudocode", "offset", "returnedSize", "originalSize",
                        "truncated", "nextOffset"}, "function.decompile result", exact=True)
    require(code["entryAddress"] == caller and code["pseudocode"],
            "function.decompile did not return fixture pseudocode")
    profile_item = None
    profile = None
    profile_cursor = None
    for _ in range(100):
        profile_params = {"name": fixture["functionName"], "limit": 50}
        if profile_cursor is not None:
            profile_params["cursor"] = profile_cursor
        profile = rpc.call("function.profile", profile_params)
        require_keys(profile, {"items", "nextCursor", "hasMore", "metrics"},
                     "function.profile result", exact=True)
        profile_item = matching_item(profile["items"], "address", caller)
        if profile_item is not None or not profile["hasMore"]:
            break
        profile_cursor = profile["nextCursor"]
        require(isinstance(profile_cursor, str) and profile_cursor,
                "function.profile continuation is missing")
    require(profile_item is not None,
            "function.profile did not return the fixture function; lastPage=%r" % profile)
    exported = rpc.call("function.export", {"addresses": [caller], "format": "json", "maxBytes": 65536})
    require_keys(exported, {"format", "content", "originalSize", "truncated"},
                 "function.export result", exact=True)
    require(exported["format"] == "json" and not exported["truncated"],
            "function.export did not return complete JSON")
    try:
        export_items = json.loads(exported["content"])
    except json.JSONDecodeError as error:
        raise AssertionError("function.export content is invalid JSON: %s" % error) from error
    require(isinstance(export_items, list) and export_items
            and export_items[0].get("entryAddress") == caller,
            "function.export content did not contain the fixture function")
    for method in ("function.analyze", "function.analyze_batch"):
        analyzed = rpc.call(method, {"addresses": [caller], "sections": ["overview"], "perSection": 10})
        require_keys(analyzed, {"sections", "items"}, "%s result" % method, exact=True)
        require(analyzed["items"] and analyzed["items"][0].get("address") == caller,
                "%s did not return the fixture function" % method)


def verify_searches(rpc, fixture):
    start = fixture["functionAddress"]
    end = fixture["functionEnd"]
    site = fixture["callSite"]
    mnemonic = fixture["instructionMnemonic"]
    pattern = " ".join(fixture["memoryBytes"][index:index + 2] for index in range(0, 8, 2))
    byte_search = rpc.call("memory.search_bytes", {"pattern": pattern, "start": start, "end": end, "limit": 20})
    require_keys(byte_search, {"items", "nextAddress", "hasMore"},
                 "memory.search_bytes result", exact=True)
    require(start in byte_search["items"], "memory.search_bytes did not find fixture bytes")
    for method in ("instruction.search", "instruction.query"):
        instructions = rpc.call(method, {"start": start, "end": end, "mnemonic": mnemonic, "limit": 100})
        require_page(instructions, "%s result" % method)
        item = matching_item(instructions["items"], "address", site)
        require(item is not None and item.get("mnemonic") == mnemonic,
                "%s did not return the fixture mnemonic/site" % method)
    instruction = rpc.call("instruction.get", {"address": site})
    require_keys(instruction, {"requestedAddress", "address", "end", "size", "kind",
                               "bytes", "mnemonic", "text", "operands"},
                 "instruction.get result", exact=True)
    require(instruction["requestedAddress"] == site and instruction["kind"] == "code",
            "instruction.get did not decode the fixture instruction")
    fixups = rpc.call("fixup.list", {"limit": 20})
    require_keys(fixups, {"items", "nextAddress", "hasMore"}, "fixup.list result", exact=True)
    for fixup in fixups["items"]:
        require_keys(fixup, {"source", "target", "type", "description", "relative",
                             "external", "unused", "created"}, "fixup.list item", exact=True)
    rpc.call_error("fixup.get", {"address": fixture["uninitializedAddress"]}, {"NOT_FOUND"})
    rpc.call_error("switch.get", {"address": fixture["nonFunctionAddress"]}, {"NOT_FOUND"})
    listing = rpc.call("listing.search", {"start": start, "end": end, "query": mnemonic, "limit": 100})
    require_keys(listing, {"items", "nextCursor", "hasMore"}, "listing.search result", exact=True)
    require(matching_item(listing["items"], "address", site) is not None,
            "listing.search did not return the fixture instruction")
    text = rpc.call("listing.search_text", {"start": start, "end": end, "query": mnemonic,
                                             "includeDisassembly": True, "includeComments": False,
                                             "limit": 100})
    require_page(text, "listing.search_text result")
    require(matching_item(text["items"], "address", site) is not None,
            "listing.search_text did not return the fixture instruction")
    signature = rpc.call("signature.make", {"mode": "function", "address": start,
                                             "format": "ida", "wildcardOperands": False,
                                             "maxLength": 1000})
    require_keys(signature, {"mode", "address", "endAddress", "signature", "format", "length", "unique"},
                 "signature.make result", exact=True)
    require(signature["address"] == start and signature["signature"],
            "signature.make did not return the fixture function signature")
    require(signature["unique"] is True, "signature.make did not produce a unique signature")
    xref_signatures = rpc.call("signature.xrefs", {
        "address": fixture["callTarget"], "wildcardOperands": False,
        "maxLength": 128, "top": 32})
    require_keys(xref_signatures, {"address", "items", "totalXrefs", "truncated"},
                 "signature.xrefs result", exact=True)
    require(matching_item(xref_signatures["items"], "xrefAddress", site) is not None,
            "signature.xrefs did not return the fixture call site")
    assembled = rpc.call("patch.assemble", {"address": site, "instruction": "nop"})
    require_keys(assembled, {"address", "bytes", "size", "instructions"},
                 "patch.assemble result", exact=True)
    require(assembled["address"] == site and assembled["bytes"],
            "patch.assemble did not assemble the fixture instruction")


def verify_inventory_and_memory(rpc, fixture):
    raw_string = base64.b64decode(fixture["stringValue"], validate=True).decode("utf-8")
    strings = rpc.call("string.search", {"query": raw_string, "minLength": 1, "limit": 100})
    require_page(strings, "string.search result")
    require(matching_item(strings["items"], "address", fixture["stringAddress"]) is not None,
            "string.search did not return the fixture string")
    regex = rpc.call("string.search_regex", {"pattern": re.escape(raw_string), "minLength": 1, "limit": 100})
    require_page(regex, "string.search_regex result")
    require(matching_item(regex["items"], "address", fixture["stringAddress"]) is not None,
            "string.search_regex did not return the fixture string")
    rpc.call_error("string.search_regex", {
        "pattern": "(a+)+$", "minLength": 1, "limit": 20}, {"INVALID_ARGUMENT"})
    rpc.call_error("listing.search_text", {
        "start": fixture["functionAddress"], "end": fixture["functionEnd"],
        "regex": "a?a?b", "includeDisassembly": True,
        "includeComments": False, "limit": 20}, {"INVALID_ARGUMENT"})
    symbol_fields = {
        "symbol.imports": {"address", "name", "module"},
        "symbol.exports": {"address", "name", "ordinal"},
        "symbol.search": {"address", "name", "kind"},
    }
    for method in ("symbol.imports", "symbol.exports", "symbol.search"):
        page = rpc.call(method, {"limit": 20})
        require_page(page, "%s result" % method)
        for item in page["items"]:
            require_keys(item, symbol_fields[method], "%s item" % method)
            require_address(item["address"], "%s item.address" % method)
    xrefs = rpc.call("xref.query", {"address": fixture["callSite"], "direction": "outgoing",
                                     "category": "code", "includeFlow": False, "limit": 100})
    require_page(xrefs, "xref.query result")
    require(any(item.get("from") == fixture["callSite"] and item.get("to") == fixture["callTarget"]
                for item in xrefs["items"]), "xref.query did not return the fixture call edge")
    memory = rpc.call("memory.read", {"address": fixture["functionAddress"], "format": "bytes", "length": 8})
    require_keys(memory, {"address", "format", "bytesRead", "value"}, "memory.read result", exact=True)
    require(memory["address"] == fixture["functionAddress"] and memory["value"] == fixture["memoryBytes"],
            "memory.read bytes do not match the fixture")


def verify_types(rpc, fixture):
    name = fixture["structName"]
    field = fixture["structField"]
    address = fixture["functionAddress"]
    for method in ("type.search", "type.query"):
        type_item = None
        result = None
        ordinal = 1
        for _ in range(100):
            result = rpc.call(method, {"name": name, "ordinal": ordinal, "limit": 100})
            require_keys(result, {"items", "nextOrdinal", "hasMore"},
                         "%s result" % method, exact=True)
            type_item = matching_item(result["items"], "name", name)
            if type_item is not None or not result["hasMore"]:
                break
            ordinal = result["nextOrdinal"]
            require(isinstance(ordinal, int) and ordinal > 0,
                    "%s continuation ordinal is invalid" % method)
        require(type_item is not None,
                "%s did not return the fixture struct; lastPage=%r" % (method, result))
    details = rpc.call("type.get", {"name": name})
    require_keys(details, {"ordinal", "name", "kind", "size", "declaration", "members", "memberCount"},
                 "type.get result")
    require(details["name"] == name and details["kind"] == "struct" and details["size"] == fixture["structSize"],
            "type.get fixture struct identity mismatch")
    require(matching_item(details["members"], "name", field) is not None,
            "type.get did not return the fixture field")
    for method in ("type.read_value", "type.read_struct"):
        value = rpc.call(method, {"address": address, "name": name, "maxBytes": 64})
        require_keys(value, {"address", "type", "bytes", "bytesRead", "originalSize",
                             "truncated", "fields", "fieldsTruncated"}, "%s result" % method, exact=True)
        require(value["address"] == address and value["type"]["name"] == name,
                "%s fixture struct identity mismatch" % method)
        require(matching_item(value["fields"], "name", field) is not None,
                "%s did not decode the fixture field" % method)
    global_value = rpc.call("global.value", {"address": address, "maxBytes": 64})
    require_keys(global_value, {"address", "symbol", "declaration", "size", "bytesRead",
                                "format", "value", "truncated"}, "global.value result", exact=True)
    require(global_value["address"] == address, "global.value address mismatch")
    stack_address = fixture["stackFrameAddress"]
    if stack_address is None:
        rpc.call_error("function.stack_frame", {"address": address}, {"NOT_FOUND"})
    else:
        frame = rpc.call("function.stack_frame", {"address": stack_address})
        require_keys(frame, {"entryAddress", "size", "variables"},
                     "function.stack_frame result", exact=True)
        require(frame["entryAddress"] == stack_address, "function.stack_frame address mismatch")
    inferred = rpc.call("type.infer", {"address": address})
    require_keys(inferred, {"address", "declaration", "source"}, "type.infer result", exact=True)
    require(inferred["address"] == address and inferred["declaration"], "type.infer fixture mismatch")
    field_xrefs = rpc.call("xref.struct_field", {"type": name, "field": field, "limit": 100})
    require_keys(field_xrefs, {"items", "truncated"}, "xref.struct_field result", exact=True)


def verify_composite_analysis(rpc, fixture):
    caller = fixture["functionAddress"]
    component = rpc.call("analysis.component", {"roots": [caller], "maxDepth": 1,
                                                 "maxNodes": 100, "maxEdges": 100,
                                                 "perFunction": 20, "sharedLimit": 20})
    require_keys(component, {"graph", "members", "sharedGlobals", "sharedStrings", "statistics", "truncated"},
                 "analysis.component result", exact=True)
    trace = rpc.call("analysis.trace_data_flow", {"address": fixture["callSite"], "direction": "both",
                                                   "maxDepth": 1, "maxNodes": 100, "maxEdges": 100})
    require_keys(trace, {"model", "nodes", "edges", "truncated"},
                 "analysis.trace_data_flow result", exact=True)
    require(trace["model"] == "xref_bfs", "analysis.trace_data_flow model mismatch")
    status = rpc.call("analysis.status", {})
    require_keys(status, {"queue", "state", "enabled", "complete", "currentAddress"},
                 "analysis.status result", exact=True)
    problems = rpc.call("analysis.problems", {"type": "disassembly", "limit": 20})
    require_keys(problems, {"items", "nextAddress", "hasMore"},
                 "analysis.problems result", exact=True)
    action = {"kind": "comment.set", "address": fixture["callSite"],
              "value": "ida-agent-temporary-diff", "expected": fixture["commentBefore"]}
    diff = rpc.call("analysis.diff_before_after", {"action": action})
    require_keys(diff, {"before", "after", "action", "changed"},
                 "analysis.diff_before_after result", exact=True)
    restored = rpc.call("changeset.preview", {"operations": [action]})
    require(restored["items"][0]["before"] == fixture["commentBefore"],
            "analysis.diff_before_after did not restore the original IDB state")
    rpc.call_error("analysis.diff_before_after", {"action": {
        "kind": "comment.set", "address": "0xffffffffffffffff", "value": "invalid"}},
        {"INVALID_ADDRESS"})
    rpc.call_error("analysis.diff_before_after", {"action": {
        "kind": "comment.set", "address": fixture["nonFunctionAddress"], "value": "missing"}},
        {"NOT_FOUND"})


def apply_changeset(rpc, operation):
    preview = rpc.call("changeset.preview", {"operations": [operation]})
    require(preview["applicable"] is True, "%s preview is not applicable" % operation["kind"])
    applied = rpc.call("changeset.apply", {
        "previewId": preview["previewId"], "operations": [operation]})
    require(applied.get("applied") is True and applied.get("changeId"),
            "%s apply failed" % operation["kind"])
    return preview, applied["changeId"]


def rollback_changeset(rpc, change_id, kind):
    try:
        result = rpc.call("changeset.rollback", {"changeId": change_id})
    except Exception as error:
        raise RuntimeError("%s rollback failed: %s" % (kind, error)) from error
    require(result.get("applied") is True, "%s rollback was not applied" % kind)


def database_segment_for(rpc, address):
    segments = rpc.call("database.segments", {"limit": 100})["items"]
    numeric = int(address, 16)
    return next(item for item in segments
                if int(item["start"], 16) <= numeric < int(item["end"], 16))


def verify_database_changesets(rpc, fixture):
    segment = database_segment_for(rpc, fixture["functionAddress"])
    temporary_name = "IDA_AGENT_SEGMENT_TEST"
    rename = {"kind": "segment.rename", "address": segment["start"],
              "value": temporary_name, "expected": segment["name"]}
    _, change_id = apply_changeset(rpc, rename)
    require(database_segment_for(rpc, fixture["functionAddress"])["name"] == temporary_name,
            "segment.rename did not change the segment name")
    rollback_changeset(rpc, change_id, "segment.rename")
    require(database_segment_for(rpc, fixture["functionAddress"])["name"] == segment["name"],
            "segment.rename rollback did not restore the name")

    permissions = segment["permissions"]
    replacement = permissions[0] + ("-" if permissions[1] == "w" else "w") + permissions[2]
    permission_change = {"kind": "segment.permissions", "address": segment["start"],
                         "value": replacement, "expected": permissions}
    _, change_id = apply_changeset(rpc, permission_change)
    require(database_segment_for(rpc, fixture["functionAddress"])["permissions"] == replacement,
            "segment.permissions did not change permissions")
    rollback_changeset(rpc, change_id, "segment.permissions")
    require(database_segment_for(rpc, fixture["functionAddress"])["permissions"] == permissions,
            "segment.permissions rollback did not restore permissions")

    function = rpc.call("function.get", {"address": fixture["functionAddress"]})
    names = (("noReturn", "noreturn"), ("library", "library"), ("static", "static"),
             ("hidden", "hidden"), ("thunk", "thunk"))
    before_flags = ",".join(name for field, name in names if function["flags"][field])
    after_values = [name for field, name in names if function["flags"][field]]
    if "library" in after_values:
        after_values.remove("library")
    else:
        after_values.append("library")
    after_flags = ",".join(name for _, name in names if name in after_values)
    flag_change = {"kind": "function.flags", "address": fixture["functionAddress"],
                   "value": after_flags, "expected": before_flags}
    _, change_id = apply_changeset(rpc, flag_change)
    changed = rpc.call("function.get", {"address": fixture["functionAddress"]})
    require(changed["flags"]["library"] != function["flags"]["library"],
            "function.flags did not toggle the library flag")
    rollback_changeset(rpc, change_id, "function.flags")
    restored = rpc.call("function.get", {"address": fixture["functionAddress"]})
    require(restored["flags"] == function["flags"],
            "function.flags rollback did not restore managed flags")

    function_end = {"kind": "function.end", "address": fixture["boundsFunctionAddress"],
                    "value": fixture["boundsExtendedEnd"],
                    "expected": fixture["boundsFunctionEnd"]}
    _, change_id = apply_changeset(rpc, function_end)
    changed = rpc.call("function.get", {"address": fixture["boundsFunctionAddress"]})
    require(changed["addressRange"]["end"] == fixture["boundsExtendedEnd"],
            "function.end did not change the entry chunk end")
    rollback_changeset(rpc, change_id, "function.end")
    restored = rpc.call("function.get", {"address": fixture["boundsFunctionAddress"]})
    require(restored["addressRange"]["end"] == fixture["boundsFunctionEnd"],
            "function.end rollback did not restore the entry chunk end")

    chunk_add = {"kind": "function.chunk.add", "address": fixture["boundsFunctionAddress"],
                 "value": fixture["tailStart"], "subject": fixture["tailEnd"]}
    _, add_change_id = apply_changeset(rpc, chunk_add)
    chunks = rpc.call("function.chunks", {
        "address": fixture["boundsFunctionAddress"], "limit": 100})
    require(any(item["kind"] == "tail" and item["start"] == fixture["tailStart"]
                and item["end"] == fixture["tailEnd"] for item in chunks["items"]),
            "function.chunk.add did not attach the tail")
    chunk_delete = {"kind": "function.chunk.delete",
                    "address": fixture["boundsFunctionAddress"],
                    "value": fixture["tailStart"], "subject": fixture["tailEnd"],
                    "expected": "owned_shared"}
    _, delete_change_id = apply_changeset(rpc, chunk_delete)
    rollback_changeset(rpc, delete_change_id, "function.chunk.delete")
    rollback_changeset(rpc, add_change_id, "function.chunk.add")
    chunks = rpc.call("function.chunks", {
        "address": fixture["boundsFunctionAddress"], "limit": 100})
    require(not any(item["kind"] == "tail" and item["start"] == fixture["tailStart"]
                    for item in chunks["items"]),
            "function chunk add/delete rollback left the tail attached")
    rpc.call_error("changeset.preview", {"operations": [{
        "kind": "function.chunk.delete", "address": fixture["tailOwner"],
        "value": fixture["tailStart"], "subject": fixture["tailEnd"]}]},
        {"INVALID_ARGUMENT"})

    rpc.call_error("changeset.preview", {"operations": [{
        "kind": "xref.code.delete", "address": fixture["callSite"],
        "value": fixture["callTarget"], "subject": "call_near"}]},
        {"INVALID_ARGUMENT"})
    rpc.call_error("changeset.preview", {"operations": [{
        "kind": "xref.code.add", "address": fixture["functionAddress"],
        "value": fixture["nonFunctionAddress"], "subject": "call_near"}]},
        {"INVALID_ADDRESS"})

    for category, xref_type, target in (
            ("code", "jump_near", fixture["callTarget"]),
            ("data", "informational", fixture["stringAddress"])):
        prefix = "xref.%s" % category
        source = fixture["functionAddress"] if category == "code" else fixture["nonFunctionAddress"]
        add = {"kind": prefix + ".add", "address": source,
               "value": target, "subject": xref_type}
        _, add_change_id = apply_changeset(rpc, add)
        xrefs = rpc.call("xref.query", {"address": source,
                                        "direction": "outgoing", "category": category,
                                        "includeFlow": False, "limit": 100})
        require(any(item["to"] == target and item["userDefined"] for item in xrefs["items"]),
                "%s.add did not create a user xref" % prefix)
        delete = {"kind": prefix + ".delete", "address": source,
                  "value": target, "subject": xref_type, "expected": "user"}
        _, delete_change_id = apply_changeset(rpc, delete)
        rollback_changeset(rpc, delete_change_id, prefix + ".delete")
        rollback_changeset(rpc, add_change_id, prefix + ".add")
        xrefs = rpc.call("xref.query", {"address": source,
                                        "direction": "outgoing", "category": category,
                                        "includeFlow": False, "limit": 100})
        require(not any(item["to"] == target and item["userDefined"] for item in xrefs["items"]),
                "%s add/delete rollback left a user xref" % prefix)


def verify_changesets(rpc, fixture):
    marker = "ida-agent-rpc-lifecycle-comment"
    operation = {"kind": "comment.set", "address": fixture["callSite"], "value": marker,
                 "expected": fixture["commentBefore"]}
    preview = rpc.call("changeset.preview", {"operations": [operation]})
    require_keys(preview, {"previewId", "items", "applicable"}, "changeset.preview result", exact=True)
    require(preview["applicable"] is True and preview["items"] == [{
        "index": 0, "before": fixture["commentBefore"], "after": marker, "conflict": False}],
        "changeset.comment.set preview mismatch")
    applied = rpc.call("changeset.apply", {"previewId": preview["previewId"], "operations": [operation]})
    require(applied.get("applied") is True and applied.get("items") == [
        {"index": 0, "applied": True, "error": None}], "changeset.comment.set apply mismatch")
    change_id = applied.get("changeId")
    require(isinstance(change_id, str) and change_id, "changeset.apply changeId is missing")
    try:
        audit = rpc.call("changeset.audit", {"limit": 1000})
        require_keys(audit, {"items"}, "changeset.audit result", exact=True)
        audit_item = next((item for item in audit["items"]
                           if item.get("changeId") == change_id and item.get("operation") == "comment.set"), None)
        require(audit_item is not None and audit_item.get("address") == fixture["callSite"]
                and audit_item.get("success") is True,
                "changeset.audit did not record the applied comment")
        require_keys(audit_item, {"changeId", "sessionId", "operation", "address", "before", "after",
                                  "success", "timestampMs"}, "changeset.audit item", exact=True)
        for field in ("sessionId", "before", "after"):
            require(re.fullmatch(r"len=\d+,fnv64=[0-9a-f]{16}", audit_item[field]) is not None,
                    "changeset.audit %s is not redacted" % field)
    finally:
        rolled_back = rpc.call("changeset.rollback", {"changeId": change_id})
        require(rolled_back.get("applied") is True and rolled_back.get("items") == [
            {"index": 0, "applied": True, "error": None}], "changeset.comment.set rollback mismatch")
    restored = rpc.call("changeset.preview", {"operations": [operation]})
    require(restored["items"][0]["before"] == fixture["commentBefore"],
            "changeset.comment.set rollback did not restore the original comment")

    original_byte = fixture["memoryBytes"][:2]
    replacement_byte = "00" if original_byte != "00" else "FF"
    patch = {"kind": "patch.bytes", "address": fixture["functionAddress"],
             "value": replacement_byte.upper(), "expected": original_byte.upper()}
    patch_preview = rpc.call("changeset.preview", {"operations": [patch]})
    require(patch_preview["applicable"] is True
            and patch_preview["items"][0]["before"] == original_byte
            and patch_preview["items"][0]["after"] == replacement_byte.lower(),
            "changeset.patch.bytes did not normalize uppercase input")
    patch_applied = rpc.call("changeset.apply", {
        "previewId": patch_preview["previewId"], "operations": [patch]})
    patch_change_id = patch_applied.get("changeId")
    require(patch_applied.get("applied") is True and patch_change_id,
            "changeset.patch.bytes uppercase apply was falsely rejected")
    patch_rollback = rpc.call("changeset.rollback", {"changeId": patch_change_id})
    require(patch_rollback.get("applied") is True,
            "changeset.patch.bytes rollback failed")
    patch_restored = rpc.call("changeset.preview", {"operations": [patch]})
    require(patch_restored["items"][0]["before"] == original_byte,
            "changeset.patch.bytes rollback did not restore the original byte")

    integer_patch = {"kind": "patch.integer", "address": fixture["functionAddress"],
                     "value": "0x1020304", "subject": "u32be",
                     "expected": fixture["memoryBytes"][:8].upper()}
    integer_preview, integer_change = apply_changeset(rpc, integer_patch)
    require(integer_preview["items"][0]["before"] == fixture["memoryBytes"][:8]
            and integer_preview["items"][0]["after"] == "01020304",
            "integer patch did not normalize expected bytes or preserve byte order")
    try:
        conflict = rpc.call("changeset.preview", {"operations": [integer_patch]})
        require(not conflict["applicable"], "integer patch accepted mismatched expected bytes")
    finally:
        rollback_changeset(rpc, integer_change, "patch.integer")
    restored = rpc.call("changeset.preview", {"operations": [integer_patch]})
    require(restored["applicable"] and restored["items"][0]["before"] == fixture["memoryBytes"][:8],
            "integer patch rollback did not restore original bytes")

    rpc.call_error("changeset.preview", {"operations": [{
        "kind": "bookmark.add", "address": fixture["callSite"], "value": "fixture bookmark"}]},
        {"INVALID_ARGUMENT"})

    verify_database_changesets(rpc, fixture)

    if not rpc.decompiler_available:
        for kind in ("local.rename", "local.type"):
            rpc.call_error("changeset.preview", {"operations": [{
                "kind": kind, "address": fixture["functionAddress"],
                "subject": "v", "value": "temporary"}]}, {"CAPABILITY_UNAVAILABLE"})
        return
    local_function = fixture["localFunctionAddress"]
    locals_before = rpc.call("decompiler.locals", {
        "address": local_function, "maxItems": 512})
    require(locals_before["items"], "fixture function has no decompiler locals")
    local = next((item for item in locals_before["items"]
                  if item["index"] == fixture["localIndex"] and item["name"]), None)
    require(local is not None, "fixture function has no named decompiler local")
    original_name = local["name"]
    original_declaration = local["declaration"]
    original_flags = local["flags"]
    local_index = local["index"]

    unset = next(item for item in locals_before["items"]
                 if item["index"] == fixture["unsetLocalIndex"])
    for kind, value in (("local.rename", "ida_agent_unsupported_unset"),
                        ("local.type", unset["declaration"])):
        rpc.call_error("changeset.preview", {"operations": [{
            "kind": kind, "address": local_function,
            "subject": unset["name"], "value": value}]}, {"CAPABILITY_UNAVAILABLE"})

    renamed = "ida_agent_temporary_local_%d" % local_index
    rename = {"kind": "local.rename", "address": local_function,
              "subject": original_name, "value": renamed, "expected": original_name}
    preview = rpc.call("changeset.preview", {"operations": [rename]})
    try:
        applied = rpc.call("changeset.apply", {"previewId": preview["previewId"], "operations": [rename]})
    except Exception as error:
        raise AssertionError("local.rename apply failed: %s" % error) from error
    changed = rpc.call("decompiler.locals", {"address": local_function, "maxItems": 512})
    require(changed["items"][local_index]["name"] == renamed
            and "user_name" in changed["items"][local_index]["flags"],
            "local.rename did not persist a user name")
    try:
        rpc.call("changeset.rollback", {"changeId": applied["changeId"]})
    except Exception as error:
        raise AssertionError("local.rename rollback failed: %s" % error) from error
    restored = rpc.call("decompiler.locals", {"address": local_function, "maxItems": 512})["items"][local_index]
    require(restored["name"] == original_name and restored["flags"] == original_flags,
            "local.rename rollback did not restore name/user markers")

    temporary_type = "unsigned int %s;" % original_name
    local_type = {"kind": "local.type", "address": local_function,
                  "subject": original_name, "value": temporary_type,
                  "expected": original_declaration}
    preview = rpc.call("changeset.preview", {"operations": [local_type]})
    try:
        applied = rpc.call("changeset.apply", {"previewId": preview["previewId"], "operations": [local_type]})
    except Exception as error:
        raise AssertionError("local.type apply failed: %s" % error) from error
    changed = rpc.call("decompiler.locals", {"address": local_function, "maxItems": 512})["items"][local_index]
    require("user_type" in changed["flags"], "local.type did not persist a user type")
    try:
        rpc.call("changeset.rollback", {"changeId": applied["changeId"]})
    except Exception as error:
        raise AssertionError("local.type rollback failed: %s" % error) from error
    restored = rpc.call("decompiler.locals", {"address": local_function, "maxItems": 512})["items"][local_index]
    require(restored["declaration"] == original_declaration and restored["flags"] == original_flags,
            "local.type rollback did not restore type/user markers")


def verify_debugger_without_process(rpc, fixture):
    requests = {
        "debugger.backends": {}, "debugger.configuration": {},
        "debugger.processes": {"limit": 1}, "debugger.select": {"name": "win32", "remote": False},
        "debugger.configure": {"host": "localhost"}, "debugger.attach": {"pid": 1234},
        "debugger.detach": {}, "debugger.suspend": {},
        "debugger.info": {}, "debugger.breakpoints": {}, "debugger.start": {},
        "debugger.exit": {}, "debugger.control": {"action": "continue"},
        "debugger.registers": {}, "debugger.stacktrace": {},
        "debugger.memory_read": {"address": fixture["functionAddress"], "length": 1},
        "debugger.memory_write": {"address": fixture["functionAddress"], "bytes": "00"},
        "debugger.threads": {"limit": 1}, "debugger.modules": {"limit": 1},
    }
    for method, params in requests.items():
        rpc.call_error(method, params, {"PERMISSION_DENIED"})


def verify_inspection_query(rpc, fixture):
    files = rpc.call("source.files", {"limit": 1})
    require_page(files, "source.files result")
    for item in files["items"]:
        require_keys(item, {"start", "end", "filename"}, "source.files item", exact=True)
        require("/" not in item["filename"] and "\\" not in item["filename"],
                "source.files leaked a path")
    if files["hasMore"]:
        require(isinstance(files["nextCursor"], int), "source.files internal cursor is invalid")
        rpc.call("source.files", {"limit": 1, "cursor": files["nextCursor"]})
    rpc.call_error("source.files", {"path": "C:/forbidden/source.cpp"}, {"INVALID_ARGUMENT"})

    lines = rpc.call("source.lines", {"start": fixture["functionAddress"],
                                      "end": fixture["functionEnd"], "limit": 10})
    require_page(lines, "source.lines result")
    for item in lines["items"]:
        require_keys(item, {"address", "line", "filename"}, "source.lines item", exact=True)
        if item["filename"] is not None:
            require("/" not in item["filename"] and "\\" not in item["filename"],
                    "source.lines leaked a path")

    demangled = rpc.call("name.demangle", {"address": fixture["functionAddress"]})
    require_keys(demangled, {"raw", "short", "long"}, "name.demangle result", exact=True)
    require(isinstance(demangled["raw"], str) and demangled["raw"],
            "name.demangle returned no raw name")

    comment_response = rpc.call_response("comment.get", {
        "address": fixture["callSite"], "scope": "item", "repeatable": False})
    if fixture["commentBefore"]:
        require("result" in comment_response, "comment.get did not return fixture comment")
        require_keys(comment_response["result"], {"address", "scope", "repeatable", "text"},
                     "comment.get result", exact=True)
    else:
        require(comment_response.get("error", {}).get("code") == "NOT_FOUND",
                "comment.get empty-comment contract mismatch")

    bookmarks = rpc.call("bookmark.list", {"limit": 10})
    require_page(bookmarks, "bookmark.list result")
    for item in bookmarks["items"]:
        require_keys(item, {"slot", "address", "line", "description"},
                     "bookmark.list item", exact=True)

    type_xrefs = rpc.call_response("type.xrefs", {"name": fixture["structName"], "limit": 10})
    if "result" in type_xrefs:
        require_page(type_xrefs["result"], "type.xrefs result")
    else:
        require(type_xrefs["error"]["code"] == "CAPABILITY_UNAVAILABLE",
                "type.xrefs missing-TID contract mismatch")

    for method in ("decompiler.locals", "decompiler.ctree"):
        params = {"address": fixture["functionAddress"]}
        if method == "decompiler.locals":
            params["maxItems"] = 100
        else:
            params.update({"maxDepth": 8, "maxNodes": 200})
        response = rpc.call_response(method, params)
        if rpc.decompiler_available:
            require("result" in response, "%s failed with decompiler available" % method)
        else:
            require(response.get("error", {}).get("code") == "CAPABILITY_UNAVAILABLE",
                    "%s unavailable capability mismatch" % method)
    if rpc.decompiler_available:
        locals_result = rpc.call("decompiler.locals", {
            "address": fixture["localFunctionAddress"], "maxItems": 512})
        require(locals_result["items"], "fixture function has no local for local_xrefs")
        local = next((item for item in locals_result["items"]
                      if item["index"] == fixture["localIndex"]), locals_result["items"][0])
        xrefs = rpc.call("decompiler.local_xrefs", {
            "address": fixture["localFunctionAddress"], "localIndex": local["index"],
            "maxDepth": 16, "maxNodes": 1000, "maxItems": 100})
        require_keys(xrefs, {"entryAddress", "localIndex", "name", "visitedNodes",
                             "totalReturned", "truncated", "items"},
                     "decompiler.local_xrefs result", exact=True)
        require(xrefs["entryAddress"] == fixture["localFunctionAddress"]
                and xrefs["localIndex"] == local["index"]
                and xrefs["name"] == local["name"]
                and xrefs["totalReturned"] == len(xrefs["items"]),
                "decompiler.local_xrefs identity/count mismatch")
        for index, item in enumerate(xrefs["items"]):
            require_keys(item, {"ordinal", "depth", "ea", "parentOp", "type"},
                         "decompiler.local_xrefs item", exact=True)
            require(item["ordinal"] == index, "decompiler.local_xrefs ordinal mismatch")
    else:
        rpc.call_error("decompiler.local_xrefs", {
            "address": fixture["functionAddress"], "localIndex": 0},
            {"CAPABILITY_UNAVAILABLE"})

    for method in ("debugger.threads", "debugger.modules"):
        response = rpc.call_response(method, {"limit": 10})
        expected = "PERMISSION_DENIED"
        require(response.get("error", {}).get("code") == expected,
                "%s should require IDA Pipe approval" % method)


def validate_fixture(fixture):
    address_fields = ("functionAddress", "functionEnd", "localFunctionAddress", "callTarget", "callSite", "nonFunctionAddress",
                      "xrefAddress", "stringAddress", "uninitializedAddress", "segmentLastAddress",
                      "boundsFunctionAddress", "boundsFunctionEnd", "boundsExtendedEnd", "tailStart", "tailEnd",
                      "tailOwner")
    for field in address_fields:
        require_address(fixture.get(field), "fixture.%s" % field)
    if fixture.get("stackFrameAddress") is not None:
        require_address(fixture["stackFrameAddress"], "fixture.stackFrameAddress")
    for field in ("functionName", "callTargetName", "instructionMnemonic", "instructionText",
                  "structName", "structField"):
        require(isinstance(fixture.get(field), str) and fixture[field],
                "fixture.%s must be non-empty" % field)
    require(isinstance(fixture.get("structSize"), int) and 1 <= fixture["structSize"] <= 64,
            "fixture.structSize is invalid")
    require(isinstance(fixture.get("localIndex"), int) and 0 <= fixture["localIndex"] <= 1000000,
            "fixture.localIndex is invalid")
    require(isinstance(fixture.get("unsetLocalIndex"), int)
            and 0 <= fixture["unsetLocalIndex"] <= 1000000,
            "fixture.unsetLocalIndex is invalid")
    require(isinstance(fixture.get("commentBefore"), str), "fixture.commentBefore must be a string")
    require(isinstance(fixture.get("memoryBytes"), str)
            and re.fullmatch(r"[0-9a-f]{16}", fixture["memoryBytes"]),
            "fixture.memoryBytes is invalid")
    require(isinstance(fixture.get("stringValue"), str) and fixture["stringValue"],
            "fixture.stringValue is invalid")


def main():
    parser = argparse.ArgumentParser(description="Verify all IDA Agent Plugin RPC methods")
    parser.add_argument("--instance-file", required=True)
    parser.add_argument("--fixture-file", required=True)
    args = parser.parse_args()

    descriptor = load_json(args.instance_file, "registry descriptor")
    fixture = load_json(args.fixture_file, "IDA fixture")
    validate_fixture(fixture)

    rpc = RpcVerifier(descriptor)
    verify_methods(rpc)
    verify_identity(rpc)
    verify_scripts(rpc)
    verify_functions(rpc, fixture)
    verify_inventory_and_memory(rpc, fixture)
    verify_searches(rpc, fixture)
    verify_types(rpc, fixture)
    verify_database(rpc, fixture)
    verify_composite_analysis(rpc, fixture)
    verify_changesets(rpc, fixture)
    verify_debugger_without_process(rpc, fixture)
    verify_inspection_query(rpc, fixture)
    for method in ("analysis.trace_argument", "analysis.guard_evidence", "analysis.trace_argument_callers"):
        rpc.call_error(method, {"callAddress": fixture["callSite"], "argumentIndex": 256}, {"INVALID_ARGUMENT"})

    # Keep queue mutation last: it is accepted asynchronously and must not be followed by a save.
    plan_end = "0x%x" % (int(fixture["functionAddress"], 16) + 1)
    plan = rpc.call("analysis.plan", {"start": fixture["functionAddress"],
                                      "end": plan_end, "confirm": True})
    require(plan == {"accepted": True, "start": fixture["functionAddress"],
                     "end": plan_end, "queue": "used"},
            "analysis.plan acceptance contract mismatch")

    expected_coverage = EXPECTED_METHODS | {"system.ping", "instance.info"}
    require(rpc.coverage == expected_coverage,
            "RPC coverage mismatch; missing=%s unexpected=%s" % (
                sorted(expected_coverage - rpc.coverage), sorted(rpc.coverage - expected_coverage)))
    print("pluginRpcCoverage=" + ",".join(sorted(rpc.coverage)))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("verify_plugin_rpc failed: %s" % error, file=sys.stderr)
        sys.exit(1)
