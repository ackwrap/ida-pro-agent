"""Pagination and IDB cache invalidation checks, for isolated test databases only."""
import argparse

from plugin_rpc_client import RpcVerifier, load_json, matching_item, require


def collect(rpc, method, address, limit):
    items, offset = [], 0
    for _ in range(4096):
        page = rpc.call(method, dict(address=address, offset=offset, limit=limit))
        items.extend(page["items"])
        if not page["hasMore"]:
            require(page["nextOffset"] is None, method + ": terminal offset")
            return items
        require(page["nextOffset"] == offset + len(page["items"])
                and page["nextOffset"] > offset, method + ": no progress")
        offset = page["nextOffset"]
    raise AssertionError(method + ": too many pages")


def apply(rpc, operation):
    preview = rpc.call("changeset.preview", {"operations": [operation]})
    require(preview["applicable"], "cache fixture mutation is not applicable")
    result = rpc.call("changeset.apply", dict(previewId=preview["previewId"], operations=[operation]))
    require(result["applied"], "cache fixture mutation failed")
    return result["changeId"]


def rollback(rpc, change):
    require(rpc.call("changeset.rollback", {"changeId": change})["applied"], "cache fixture rollback failed")


def verify(rpc, fixture):
    caller, target = fixture["functionAddress"], fixture["callTarget"]
    bounds = fixture["boundsFunctionAddress"]
    for method in ("function.disassemble", "function.basic_blocks", "function.callees"):
        expected = collect(rpc, method, caller, 100)
        require(collect(rpc, method, caller, 1) == expected, method + ": sequential pages differ")
        for offset in (len(expected), 1, 0):
            page = rpc.call(method, dict(address=caller, offset=offset, limit=3))
            require(page["items"] == expected[offset:offset + 3], method + ": random page differs")

    original = collect(rpc, "function.callees", caller, 100)
    callee = matching_item(original, "address", target)
    require(callee is not None, "fixture callee missing")
    change = apply(rpc, dict(kind="rename", address=target,
                            expected=callee["name"], value="ida_cache_renamed_target"))
    try:
        renamed = collect(rpc, "function.callees", caller, 100)
        require(matching_item(renamed, "address", target)["name"] == "ida_cache_renamed_target",
                "callee cache survived rename")
    finally:
        rollback(rpc, change)
    require(collect(rpc, "function.callees", caller, 100) == original, "callee cache survived rollback")

    original = collect(rpc, "function.callees", bounds, 100)
    change = apply(rpc, dict(kind="xref.code.add", address=bounds, value=target, subject="call_near"))
    try:
        require(matching_item(collect(rpc, "function.callees", bounds, 100), "address", target) is not None,
                "callee cache survived xref creation")
    finally:
        rollback(rpc, change)
    require(collect(rpc, "function.callees", bounds, 100) == original, "callee cache survived xref rollback")

    original_blocks = collect(rpc, "function.basic_blocks", bounds, 100)
    original_code = collect(rpc, "function.disassemble", bounds, 100)
    change = apply(rpc, dict(kind="function.end", address=bounds,
                            expected=fixture["boundsFunctionEnd"], value=fixture["boundsExtendedEnd"]))
    try:
        extended = collect(rpc, "function.basic_blocks", bounds, 100)
        require(extended != original_blocks, "block cache survived function resize")
        require(len(collect(rpc, "function.disassemble", bounds, 1)) > len(original_code),
                "disassembly did not include extended instructions")
    finally:
        rollback(rpc, change)
    require(collect(rpc, "function.basic_blocks", bounds, 100) == original_blocks,
            "block cache survived resize rollback")

    change = apply(rpc, dict(kind="function.chunk.add", address=bounds,
                            value=fixture["tailStart"], subject=fixture["tailEnd"]))
    try:
        expected = collect(rpc, "function.disassemble", bounds, 100)
        require(len(expected) > len(original_code), "shared tail fixture has no instructions")
        require(collect(rpc, "function.disassemble", bounds, 1) == expected,
                "sequential disassembly skipped/repeated a shared tail")
        # Leave a continuation cached, then remove its tail to test invalidation.
        rpc.call("function.disassemble", dict(address=bounds, limit=len(original_code)))
    finally:
        rollback(rpc, change)
    page = rpc.call("function.disassemble", dict(address=bounds, offset=len(original_code), limit=1))
    require(page["items"] == [] and not page["hasMore"], "continuation survived tail removal")
    print("function_pagination=ok cache_invalidation=ok shared_tail=ok", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--instance-file", required=True)
    parser.add_argument("--ready-file", required=True)
    args = parser.parse_args()
    verify(RpcVerifier(load_json(args.instance_file, "instance")), load_json(args.ready_file, "fixture"))
