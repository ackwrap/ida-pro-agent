---
name: idapython
description: IDA Pro Python scripting for reverse engineering through ida-mcp's ida_scripts tool and script.execute method. Use when the user explicitly requests an IDAPython script or a supported domain tool cannot express the requested operation. Covers ida_* modules, idautils iterators, Hex-Rays, and common patterns.
license: MIT
---

# IDAPython

Requires ida-mcp's `ida_scripts` MCP tool with the `script.execute` method and an IDA instance with IDAPython; Hex-Rays examples require a decompiler license.

Use `action: "describe"` on `ida_scripts` to obtain the current `script.execute` schema, then `action: "call"` with `method: "script.execute"` and its inputs nested in `arguments`.

Use modern `ida_*` modules. Avoid legacy `idc` module.

Prefer the Gateway's advertised direct read tools (such as `ida_get_function` and `ida_read_memory`) or bounded domain tools for reads and its reversible ChangeSet workflow for supported IDB edits. Use `script.execute` only when the user explicitly requests arbitrary scripting or the requested operation has no supported tool contract. It is an arbitrary-code side-effecting tool governed by the MCP client's permission system; the Gateway does not prompt separately. Never add authorization fields to tool arguments.

On argument errors, correct fields using `issues`/`hint`, or refresh `script.execute` with `describe` on older Gateways. The Gateway never automatically retries scripts. A timeout may leave execution in progress (`executionState:"unknown"`); inspect the actual outcome before resubmitting code.

## Module Router

| Task | Module | Key Items |
|------|--------|-----------|
| Bytes/memory | `ida_bytes` | `get_bytes`, `patch_bytes`, `get_flags`, `create_*` |
| Functions | `ida_funcs` | `func_t`, `get_func`, `add_func`, `get_func_name` |
| Names | `ida_name` | `set_name`, `get_name`, `demangle_name` |
| Types | `ida_typeinf` | `tinfo_t`, `apply_tinfo`, `parse_decl` |
| Decompiler | `ida_hexrays` | `decompile`, `cfunc_t`, `lvar_t`, ctree visitor |
| Segments | `ida_segment` | `segment_t`, `getseg`, `add_segm` |
| Xrefs | `ida_xref` | `xrefblk_t`, `add_cref`, `add_dref` |
| Instructions | `ida_ua` | `insn_t`, `op_t`, `decode_insn` |
| Stack frames | `ida_frame` | `get_frame`, `define_stkvar` |
| Iteration | `idautils` | `Functions()`, `Heads()`, `XrefsTo()`, `Strings()` |
| UI/dialogs | `ida_kernwin` | `msg`, `ask_*`, `jumpto`, `Choose` |
| Database info | `ida_ida` | `inf_get_*`, `inf_is_64bit()` |
| Analysis | `ida_auto` | `auto_wait`, `plan_and_wait` |
| Flow graphs | `ida_gdl` | `FlowChart`, `BasicBlock` |
| Register tracking | `ida_regfinder` | `find_reg_value`, `reg_value_info_t` |

## Core Patterns

### Iterate functions
```python
import ida_funcs
import idautils

for ea in idautils.Functions():
    name = ida_funcs.get_func_name(ea)
    func = ida_funcs.get_func(ea)
```

### Iterate instructions in function
```python
import ida_ua
import idautils

for head in idautils.FuncItems(func_ea):
    insn = ida_ua.insn_t()
    if ida_ua.decode_insn(insn, head):
        print(f"{head:#x}: {insn.itype}")
```

### Cross-references
```python
import idautils

for xref in idautils.XrefsTo(ea):
    print(f"{xref.frm:#x} -> {xref.to:#x} type={xref.type}")
```

### Read/write bytes
```python
import ida_bytes

data = ida_bytes.get_bytes(ea, size)
ida_bytes.patch_bytes(ea, b"\x90\x90")
```

### Names
```python
import ida_name

name = ida_name.get_name(ea)
ida_name.set_name(ea, "new_name", ida_name.SN_NOCHECK)
```

### Decompile function
```python
import ida_hexrays

cfunc = ida_hexrays.decompile(ea)
if cfunc:
    print(cfunc)  # pseudocode
    for lvar in cfunc.lvars:
        print(f"{lvar.name}: {lvar.type()}")
```

### Walk ctree (decompiled AST)
```python
import ida_hexrays

class MyVisitor(ida_hexrays.ctree_visitor_t):
    def visit_expr(self, e):
        if e.op == ida_hexrays.cot_call:
            print(f"Call at {e.ea:#x}")
        return 0

cfunc = ida_hexrays.decompile(ea)
MyVisitor().apply_to(cfunc.body, None)
```

### Apply type
```python
import ida_typeinf

tif = ida_typeinf.tinfo_t()
if ida_typeinf.parse_decl(tif, None, "int (*)(char *, int)", 0):
    ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE)
```

### Create structure
```python
import ida_typeinf

udt = ida_typeinf.udt_type_data_t()
m = ida_typeinf.udm_t()
m.name = "field1"
m.type = ida_typeinf.tinfo_t(ida_typeinf.BTF_INT32)
m.offset = 0
m.size = 4
udt.push_back(m)
tif = ida_typeinf.tinfo_t()
tif.create_udt(udt, ida_typeinf.BTF_STRUCT)
tif.set_named_type(ida_typeinf.get_idati(), "MyStruct")
```

### Strings list
```python
import idautils

for s in idautils.Strings():
    print(f"{s.ea:#x}: {str(s)}")
```

### Wait for analysis
```python
import ida_auto

ida_auto.auto_wait()  # Block until autoanalysis completes
```

## Key Constants

| Constant | Value/Use |
|----------|-----------|
| `BADADDR` | Invalid address sentinel |
| `ida_name.SN_NOCHECK` | Skip name validation |
| `ida_typeinf.TINFO_DEFINITE` | Force type application |
| `o_reg`, `o_mem`, `o_imm`, `o_displ`, `o_near` | Operand types |
| `dt_byte`, `dt_word`, `dt_dword`, `dt_qword` | Data types |
| `fl_CF`, `fl_CN`, `fl_JF`, `fl_JN`, `fl_F` | Code xref types |
| `dr_R`, `dr_W`, `dr_O` | Data xref types |

## Critical Rules

1. **Validate addresses**: Parse user-provided values with `int(value, 0)`, reject invalid values, and treat `ea_t` as potentially 64-bit.
2. **Wait only when necessary**: Use `ida_auto.auto_wait()` only when the result depends on completed autoanalysis; it blocks IDA and may outlive an MCP timeout.
3. **Respect IDA threading**: Gateway script execution enters through `IdaExecutor`. Do not spawn threads that call IDA APIs, and do not wrap the script in another synchronous UI-thread dispatch.
4. **Bound work and output**: Avoid unbounded database scans and large prints. A client timeout does not prove that started Python code stopped.
5. **Treat scripts as arbitrary code**: They may modify the IDB, access files or networks, launch processes, and block IDA. Keep the code minimal and disclose material side effects before execution.

## Anti-Patterns

| Avoid | Do Instead |
|-------|------------|
| `idc.*` functions | Use `ida_*` modules |
| Hardcoded addresses | Use names, patterns, or xrefs |
| Assuming 32-bit addresses | Parse and validate full-width `ea_t` values |
| Spawning IDA API worker threads | Keep IDA API work in the Gateway-dispatched script |
| Broad prints or scans | Return a small summary or bounded result |
| Guessing at types | Derive from disassembly/decompilation |

## Detailed API Reference

For comprehensive documentation on any module, read `docs/<module>.md`:
- **High-use**: `ida_bytes`, `ida_funcs`, `ida_hexrays`, `ida_typeinf`, `ida_name`, `idautils`
- **Medium-use**: `ida_segment`, `ida_xref`, `ida_ua`, `ida_frame`, `ida_kernwin`
- **Specialized**: `ida_dbg` (debugger), `ida_nalt` (netnode storage), `ida_regfinder` (register tracking)

For exact signatures, consult the official IDAPython documentation matching the installed IDA version.
