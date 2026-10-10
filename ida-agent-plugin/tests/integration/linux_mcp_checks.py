"""Mutating and failure-path checks on the runner's disposable Linux database."""
import json


def expect_error(client, domain, method, arguments, code):
    result = client.request("tools/call", {"name": "ida_" + domain, "arguments": {
        "action": "call", "method": method, "arguments": arguments}})
    assert result.get("isError"), (method, result)
    assert code + ":" in "\n".join(item.get("text", "") for item in result["content"]), (method, result)


def verify_functional_mcp(client, fixture, root):
    call = client.call
    # The scripts only read/modify this runner's disposable IDB.
    python = call("scripts", "script.execute", {
        "language": "python", "code": "print('Linux 脚本✓')"})
    assert python["success"] and python["stdout"] == "Linux 脚本✓\n", python
    failed = call("scripts", "script.execute", {
        "language": "python", "code": "raise ValueError('linux-script-error')"})
    assert not failed["success"] and "linux-script-error" in failed["stderr"], failed
    bounded = call("scripts", "script.execute", {
        "language": "python", "code": "print('界' * 12000, end='')"})
    assert bounded["success"] and bounded["truncated"] and bounded["originalSize"] == 36000, bounded
    assert len(bounded["stdout"].encode("utf-8")) <= 32768
    idc = call("scripts", "script.execute", {"language": "idc", "code": "return 6 * 7;"})
    assert idc["success"] and idc["result"] is not None, idc
    source = root / "脚本 with spaces.py"
    source.write_text("print('file-source-ok')\n", encoding="utf-8")
    from_file = call("scripts", "script.execute", {"language": "python", "path": str(source)})
    assert from_file["success"] and from_file["stdout"] == "file-source-ok\n", from_file
    expect_error(client, "scripts", "script.execute", {"language": "python",
        "path": str(source), "code": "print('ambiguous')"}, "INVALID_ARGUMENT")

    address = fixture["functionAddress"]
    original = call("functions", "function.get", {"address": address})
    renamed = "linux_mcp_renamed"
    operation = {"kind": "rename", "address": address, "value": renamed, "expected": original["name"]}
    preview = call("changes", "changeset.preview", {"operations": [operation]})
    assert preview["applicable"], preview
    applied = call("changes", "changeset.apply", {"previewId": preview["previewId"], "operations": [operation]})
    assert applied["applied"], applied
    try:
        assert call("functions", "function.get", {"address": address})["name"] == renamed
        audit = call("changes", "changeset.audit", {"limit": 1000})
        assert any(item["changeId"] == applied["changeId"] and item["success"] for item in audit["items"])
        conflict = dict(operation, value="linux_mcp_conflict")
        rejected = call("changes", "changeset.preview", {"operations": [conflict]})
        assert not rejected["applicable"] and rejected["items"][0]["conflict"], rejected
    finally:
        assert call("changes", "changeset.rollback", {"changeId": applied["changeId"]})["applied"]
    assert call("functions", "function.get", {"address": address})["name"] == original["name"]

    # Exercise Gateway-only patch wrappers, including expected-byte guards.
    memory = {"address": address, "format": "bytes", "length": 4}
    before = call("search", "memory.read", memory)["value"]
    for method, arguments in (
        ("patch.write_bytes", {"address": address, "bytes": "01020304", "expectedBytes": before}),
        ("patch.write_integer", {"address": address, "value": "0x1020304", "integerType": "u32be", "expectedBytes": before}),
    ):
        patch = call("patch", method, arguments)
        assert patch["applied"] and patch["before"] == before and patch["after"] == "01020304", patch
        try:
            assert call("search", "memory.read", memory)["value"] == "01020304"
            expect_error(client, "patch", method, arguments, "CONFLICT")
        finally:
            assert call("changes", "changeset.rollback", {"changeId": patch["changeId"]})["applied"]
        assert call("search", "memory.read", memory)["value"] == before

    # The same cursor is invalid under different normalized filters or a forged signature.
    page = call("database", "database.segments", {"limit": 1})
    assert page["hasMore"], page
    token = page["nextCursor"]
    tampered = ("A" if token[0] != "A" else "B") + token[1:]
    expect_error(client, "database", "database.segments", {"limit": 1, "cursor": tampered}, "INVALID_ARGUMENT")
    expect_error(client, "functions", "function.search", {"name": "*", "limit": 1, "cursor": token}, "INVALID_ARGUMENT")

    # Headless IDA must preserve production consent behavior for every debugger path.
    for method, arguments in (("debugger.backends", {}), ("debugger.start", {}),
                              ("debugger.memory_write", {"address": address, "bytes": "00"})):
        expect_error(client, "debugger", method, arguments, "PERMISSION_DENIED")
    saved = call("database", "database.save", {"compact": False, "backup": False})
    assert saved["saved"] and not saved["explicitTarget"], saved
    summary = {"scripts": True, "changesets": True, "patchRollback": True,
        "conflicts": True, "cursorIntegrity": True, "headlessConsent": True, "save": True}
    (root / (type(client).__name__ + "-functional.json")).write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print("functional_mcp=" + type(client).__name__ + " " + json.dumps(summary), flush=True)
