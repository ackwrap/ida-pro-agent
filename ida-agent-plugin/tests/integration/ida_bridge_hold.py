import base64
import json
import os
import threading
import time

import idautils
import idc
import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_ida
import ida_idaapi
import ida_kernwin
import ida_loader
import ida_lines
import ida_pro
import ida_segment
import ida_typeinf
import ida_ua
import ida_xref


_hold_thread = None
_exit_code = 0


def hold_until_release(release_file):
    global _exit_code

    hold_seconds = int(os.environ.get("IDA_AGENT_TEST_HOLD_SECONDS", "120"))
    deadline = time.monotonic() + hold_seconds
    while not os.path.exists(release_file):
        if time.monotonic() >= deadline:
            ida_kernwin.msg("[ida-agent-test] bridge hold timed out\n")
            _exit_code = 1
            ida_kernwin.stop_serving()
            return
        time.sleep(0.05)
    ida_kernwin.stop_serving()


def find_non_function_address():
    checked = 0
    max_candidates = 100000
    for index in range(ida_segment.get_segm_qty()):
        segment = ida_segment.getnseg(index)
        if segment is None or segment.start_ea >= segment.end_ea:
            continue
        address = segment.start_ea
        while address < segment.end_ea and checked < max_candidates:
            checked += 1
            if ida_bytes.is_mapped(address) and ida_funcs.get_func_start(address) == ida_idaapi.BADADDR:
                return address
            next_address = ida_bytes.next_head(address, segment.end_ea)
            if next_address == ida_idaapi.BADADDR or next_address <= address:
                break
            address = next_address
    return ida_idaapi.BADADDR


def find_xref_source():
    checked = 0
    max_candidates = 100000
    for index in range(ida_segment.get_segm_qty()):
        segment = ida_segment.getnseg(index)
        if segment is None or segment.start_ea >= segment.end_ea:
            continue
        address = segment.start_ea
        while address < segment.end_ea and checked < max_candidates:
            checked += 1
            xref = ida_xref.xrefblk_t()
            count = 0
            ok = xref.first_from(address, ida_xref.XREF_NOFLOW | ida_xref.XREF_EA)
            while ok and count < 2:
                count += 1
                ok = xref.next_from()
            if count >= 2:
                return address
            next_address = ida_bytes.next_head(address, segment.end_ea)
            if next_address == ida_idaapi.BADADDR or next_address <= address:
                break
            address = next_address
    return ida_idaapi.BADADDR


def find_direct_call_relationship():
    fallback = None
    for caller_address in idautils.Functions():
        caller = ida_funcs.get_func(caller_address)
        if caller is None:
            continue
        for site in idautils.FuncItems(caller.start_ea):
            for xref in idautils.XrefsFrom(site, 0):
                if xref.type not in (ida_xref.fl_CF, ida_xref.fl_CN):
                    continue
                target = ida_funcs.get_func(xref.to)
                if target is None or xref.to != target.start_ea:
                    continue
                relationship = (caller.start_ea, target.start_ea, site)
                if target.start_ea != caller.start_ea:
                    incoming_calls = [
                        incoming
                        for incoming in idautils.XrefsTo(target.start_ea, 0)
                        if incoming.type in (ida_xref.fl_CF, ida_xref.fl_CN)
                    ]
                    if 1 <= len(incoming_calls) <= 32:
                        return relationship
                    if fallback is None:
                        fallback = relationship
                if fallback is None:
                    fallback = relationship
    return fallback


def create_fixture_struct():
    name = "ida_agent_fixture_struct"
    definition = (
        "struct ida_agent_fixture_struct { "
        "unsigned int magic; unsigned short tag; "
        "unsigned char flags; unsigned char reserved; };"
    )
    existing = ida_typeinf.tinfo_t()
    if existing.get_named_type(None, name):
        ida_typeinf.del_named_type(None, name, ida_typeinf.NTF_TYPE)
    if idc.set_local_type(-1, definition, idc.PT_SIL) == 0:
        return None
    stored = ida_typeinf.tinfo_t()
    if not stored.get_named_type(None, name) or not stored.is_struct():
        return None
    return name, int(stored.get_size())


def find_stack_frame_address(preferred_address):
    candidates = [preferred_address]
    candidates.extend(address for address in idautils.Functions() if address != preferred_address)
    for address in candidates:
        function = ida_funcs.get_func(address)
        if function is not None and function.frame_object:
            return function.start_ea
    return ida_idaapi.BADADDR


def find_named_local_function(preferred_address):
    candidates = [preferred_address]
    candidates.extend(address for address in idautils.Functions() if address != preferred_address)
    fallback = None
    for address in candidates[:5000]:
        try:
            function = ida_hexrays.decompile(
                address,
                flags=ida_hexrays.DECOMP_NO_WAIT | ida_hexrays.DECOMP_GXREFS_NOUPD,
            )
        except Exception:
            continue
        if function is None:
            continue
        unset = [(index, variable) for index, variable in enumerate(function.get_lvars())
                 if str(variable.name) and not variable.has_user_name and not variable.has_user_type]
        if len(unset) < 2:
            continue
        primary = next((item for item in unset
                        if item[1].type().is_integral() and item[1].width == 4), None)
        if primary is None:
            continue
        unsupported = next(item for item in unset if item[0] != primary[0])
        return address, primary[0], unsupported[0]
    return fallback


def seed_local_user_settings(address, index):
    function = ida_hexrays.decompile(address)
    if function is None or index >= len(function.get_lvars()):
        return False
    variable = function.get_lvars()[index]
    original_name = str(variable.name)
    baseline_name = "ida_agent_fixture_local_%d" % index
    if not ida_hexrays.rename_lvar(address, original_name, baseline_name):
        return False
    function = ida_hexrays.decompile(address)
    variable = function.get_lvars()[index]
    info = ida_hexrays.lvar_saved_info_t()
    if not ida_hexrays.locate_lvar(info.ll, address, str(variable.name)):
        return False
    info.type = variable.type()
    return ida_hexrays.modify_user_lvar_info(address, ida_hexrays.MLI_TYPE, info)


def find_utf8_string():
    for string in idautils.Strings():
        value = str(string)
        encoded = value.encode("utf-8")
        if not encoded or len(encoded) > 256:
            continue
        address = int(string.ea)
        raw = ida_bytes.get_bytes(address, len(encoded) + 1)
        if raw == encoded + b"\0":
            return address, encoded
    return ida_idaapi.BADADDR, b""


def find_uninitialized_address():
    segments = [ida_segment.getnseg(index) for index in range(ida_segment.get_segm_qty())]
    segments.sort(key=lambda segment: 0 if segment is not None and segment.type == ida_segment.SEG_BSS else 1)
    for segment in segments:
        if segment is None or segment.start_ea >= segment.end_ea:
            continue
        candidate_count = min(4096, segment.end_ea - segment.start_ea)
        for offset in range(candidate_count):
            address = segment.start_ea + offset
            if ida_bytes.is_mapped(address) and not ida_bytes.is_loaded(address):
                return address
    return ida_idaapi.BADADDR


def create_function_mutation_fixture():
    maximum = ida_ida.inf_get_max_ea()
    base = (maximum + 0x10000) & ~0xFFFF
    if base <= maximum or base + 0x1000 >= ida_idaapi.BADADDR:
        return None
    if not idc.add_segm_ex(base, base + 0x1000, 0, 2, idc.saRelPara, idc.scPub,
                           idc.ADDSEG_NOSREG | idc.ADDSEG_QUIET):
        return None
    if not idc.set_segm_name(base, "IDA_AGENT_TEST") or not idc.set_segm_class(base, "CODE"):
        return None
    idc.set_segm_attr(base, idc.SEGATTR_PERM, ida_segment.SEGPERM_READ | ida_segment.SEGPERM_EXEC)

    tail_start = base
    function_start = base + 0x10
    second_owner = base + 0x20
    ida_bytes.patch_bytes(tail_start, b"\x90")
    ida_bytes.patch_bytes(function_start, b"\x90\xc3\x90")
    ida_bytes.patch_bytes(second_owner, b"\x90\xc3")
    for address in (tail_start, function_start, function_start + 1, function_start + 2,
                    second_owner, second_owner + 1):
        if ida_ua.create_insn(address) <= 0:
            return None
    if not ida_funcs.add_func(function_start, function_start + 2) or not ida_funcs.add_func(second_owner, second_owner + 2):
        return None
    if not ida_funcs.append_func_tail_ea(second_owner, tail_start, tail_start + 1):
        return None
    return {
        "tailStart": "0x%x" % tail_start,
        "tailEnd": "0x%x" % (tail_start + 1),
        "tailOwner": "0x%x" % second_owner,
        "boundsFunctionAddress": "0x%x" % function_start,
        "boundsFunctionEnd": "0x%x" % (function_start + 2),
        "boundsExtendedEnd": "0x%x" % (function_start + 3),
    }


def main():
    global _hold_thread, _exit_code

    ida_auto.auto_wait()
    if not ida_loader.load_and_run_plugin("ida-agent-plugin", 0):
        ida_kernwin.msg("[ida-agent-test] load_and_run_plugin failed\n")
        ida_pro.qexit(1)
        return

    release_file = os.environ.get("IDA_AGENT_TEST_RELEASE_FILE", "")
    if not release_file:
        ida_kernwin.msg("[ida-agent-test] release file is not configured\n")
        ida_pro.qexit(1)
        return

    ida_kernwin.msg("[ida-agent-test] bridge ready\n")
    ready_file = os.environ.get("IDA_AGENT_TEST_READY_FILE", "")
    if not ready_file:
        ida_kernwin.msg("[ida-agent-test] ready file is not configured\n")
        ida_pro.qexit(1)
        return
    call_relationship = find_direct_call_relationship()
    if call_relationship is None:
        ida_kernwin.msg("[ida-agent-test] no direct function call relationship is available\n")
        ida_pro.qexit(1)
        return
    function_address, call_target, call_site = call_relationship
    function = ida_funcs.get_func(function_address)
    target_function = ida_funcs.get_func(call_target)
    if function is None or target_function is None or function.end_ea <= function.start_ea:
        ida_kernwin.msg("[ida-agent-test] direct call functions are unavailable\n")
        ida_pro.qexit(1)
        return
    function_mutation_fixture = create_function_mutation_fixture()
    if function_mutation_fixture is None:
        ida_kernwin.msg("[ida-agent-test] function mutation fixture could not be created\n")
        ida_pro.qexit(1)
        return
    instruction_mnemonic = ida_ua.print_insn_mnem(call_site)
    instruction_text = ida_lines.generate_disasm_line(call_site, ida_lines.GENDSM_REMOVE_TAGS)
    if not instruction_mnemonic or not instruction_text:
        ida_kernwin.msg("[ida-agent-test] call instruction text is unavailable\n")
        ida_pro.qexit(1)
        return
    fixture_struct = create_fixture_struct()
    if fixture_struct is None:
        ida_kernwin.msg("[ida-agent-test] local fixture struct could not be created\n")
        ida_pro.qexit(1)
        return
    struct_name, struct_size = fixture_struct
    stack_frame_address = find_stack_frame_address(function_address)
    local_fixture = find_named_local_function(function_address)
    if local_fixture is None:
        ida_kernwin.msg("[ida-agent-test] no function with a named decompiler local is available\n")
        ida_pro.qexit(1)
        return
    local_function_address, local_index, unset_local_index = local_fixture
    if not seed_local_user_settings(local_function_address, local_index):
        ida_kernwin.msg("[ida-agent-test] could not seed local user settings\n")
        ida_pro.qexit(1)
        return
    non_function_address = find_non_function_address()
    if non_function_address == ida_idaapi.BADADDR:
        ida_kernwin.msg("[ida-agent-test] no mapped non-function address is available\n")
        ida_pro.qexit(1)
        return
    xref_address = find_xref_source()
    if xref_address == ida_idaapi.BADADDR:
        ida_kernwin.msg("[ida-agent-test] no paginated xref source is available\n")
        ida_pro.qexit(1)
        return
    memory_bytes = ida_bytes.get_bytes(function_address, 8)
    if memory_bytes is None or len(memory_bytes) != 8:
        ida_kernwin.msg("[ida-agent-test] function bytes are unavailable\n")
        ida_pro.qexit(1)
        return
    string_address, string_value = find_utf8_string()
    if string_address == ida_idaapi.BADADDR:
        ida_kernwin.msg("[ida-agent-test] no UTF-8 string is available\n")
        ida_pro.qexit(1)
        return
    uninitialized_address = find_uninitialized_address()
    if uninitialized_address == ida_idaapi.BADADDR:
        ida_kernwin.msg("[ida-agent-test] no uninitialized address is available\n")
        ida_pro.qexit(1)
        return
    function_segment = ida_segment.getseg(function_address)
    if function_segment is None or function_segment.end_ea <= function_segment.start_ea:
        ida_kernwin.msg("[ida-agent-test] function segment is unavailable\n")
        ida_pro.qexit(1)
        return
    _hold_thread = threading.Thread(
        target=hold_until_release,
        args=(release_file,),
        daemon=True,
    )
    _hold_thread.start()
    ready_temp = ready_file + ".tmp"
    with open(ready_temp, "w", encoding="utf-8") as ready:
        json.dump(
            dict({
                "functionAddress": "0x%x" % function_address,
                "functionEnd": "0x%x" % function.end_ea,
                "functionName": ida_funcs.get_func_name(function.start_ea),
                "localFunctionAddress": "0x%x" % local_function_address,
                "localIndex": local_index,
                "unsetLocalIndex": unset_local_index,
                "callTarget": "0x%x" % call_target,
                "callTargetName": ida_funcs.get_func_name(target_function.start_ea),
                "callSite": "0x%x" % call_site,
                "instructionMnemonic": instruction_mnemonic,
                "instructionText": instruction_text,
                "structName": struct_name,
                "structSize": struct_size,
                "structField": "magic",
                "stackFrameAddress": (
                    None
                    if stack_frame_address == ida_idaapi.BADADDR
                    else "0x%x" % stack_frame_address
                ),
                "commentBefore": ida_bytes.get_cmt(call_site, False) or "",
                "nonFunctionAddress": "0x%x" % non_function_address,
                "xrefAddress": "0x%x" % xref_address,
                "memoryBytes": memory_bytes.hex(),
                "stringAddress": "0x%x" % string_address,
                "stringValue": base64.b64encode(string_value).decode("ascii"),
                "uninitializedAddress": "0x%x" % uninitialized_address,
                "segmentLastAddress": "0x%x" % (function_segment.end_ea - 1),
            }, **function_mutation_fixture),
            ready,
        )
    os.replace(ready_temp, ready_file)
    ida_kernwin.serve()
    if _exit_code == 0:
        ida_kernwin.msg("[ida-agent-test] lifecycle passed\n")
    ida_pro.qexit(_exit_code)


main()
