package mcpserver

const changeOperationSchema = `{
  "type":"object","additionalProperties":false,"required":["kind","value"],
  "properties":{
    "kind":{"type":"string","enum":["rename","comment.set","comment.append","comment.pseudocode","bookmark.add","type.apply","patch.bytes","patch.integer","define.function","define.code","undefine","decompiler.invalidate","define.data","operand.hex","operand.decimal","operand.character","operand.binary","operand.octal","operand.offset","operand.struct_offset","operand.stack_variable","type.declare","enum.upsert","decompiler.invalidate_all","stack.declare","stack.delete","local.rename","local.type","segment.rename","segment.permissions","xref.code.add","xref.code.delete","xref.data.add","xref.data.delete","function.flags","function.end","function.chunk.add","function.chunk.delete"]},
    "address":` + addressSchema + `,
    "value":{"type":"string","maxLength":65536},
    "expected":{"type":"string","maxLength":65536},
    "repeatable":{"type":"boolean"},
    "offset":{"type":"integer","minimum":-9223372036854775808,"maximum":9223372036854775807},
    "size":{"type":"integer","minimum":1,"maximum":4294967295},
    "subject":{"type":"string","minLength":1,"maxLength":1024}
  },
  "allOf":[
    {"if":{"properties":{"kind":{"enum":["type.declare","enum.upsert","decompiler.invalidate_all"]}},"required":["kind"]},"then":{"not":{"required":["address"]}},"else":{"required":["address"]}},
    {"if":{"required":["repeatable"]},"then":{"properties":{"kind":{"enum":["comment.set","comment.append"]}}}},
    {"if":{"required":["offset"]},"then":{"properties":{"kind":{"enum":["operand.struct_offset","stack.declare","stack.delete"]}}}},
    {"if":{"properties":{"kind":{"enum":["stack.declare","stack.delete"]}},"required":["kind"]},"then":{"required":["offset"]}},
    {"if":{"required":["size"]},"then":{"properties":{"kind":{"const":"stack.delete"}}}},
    {"if":{"properties":{"kind":{"const":"stack.delete"}},"required":["kind"]},"then":{"required":["size"]}},
    {"if":{"required":["subject"]},"then":{"properties":{"kind":{"enum":["patch.integer","operand.offset","operand.struct_offset","local.rename","local.type","xref.code.add","xref.code.delete","xref.data.add","xref.data.delete","function.chunk.add","function.chunk.delete"]}}}},
    {"if":{"properties":{"kind":{"enum":["patch.integer","operand.struct_offset","local.rename","local.type","xref.code.add","xref.code.delete","xref.data.add","xref.data.delete","function.chunk.add","function.chunk.delete"]}},"required":["kind"]},"then":{"required":["subject"]}},
    {"if":{"properties":{"kind":{"pattern":"^operand\\."}},"required":["kind"]},"then":{"properties":{"value":{"pattern":"^[0-7]$"}}}},
    {"if":{"properties":{"kind":{"const":"bookmark.add"}},"required":["kind"]},"then":{"properties":{"value":{"minLength":1,"maxLength":1024}}}},
    {"if":{"properties":{"kind":{"const":"patch.bytes"}},"required":["kind"]},"then":{"properties":{"value":{"minLength":2,"pattern":"^(?:[0-9A-Fa-f]{2})+$"}}}},
    {"if":{"properties":{"kind":{"const":"patch.integer"}},"required":["kind"]},"then":{"properties":{"subject":{"pattern":"^[ui](?:8|16|32|64)(?:le|be)?$"}}}},
    {"if":{"properties":{"kind":{"const":"decompiler.invalidate_all"}},"required":["kind"]},"then":{"properties":{"value":{"const":""}}}},
    {"if":{"properties":{"kind":{"const":"segment.rename"}},"required":["kind"]},"then":{"properties":{"value":{"minLength":1,"maxLength":255}}}},
    {"if":{"properties":{"kind":{"const":"segment.permissions"}},"required":["kind"]},"then":{"properties":{"value":{"pattern":"^[r-][w-][x-]$"}}}},
    {"if":{"properties":{"kind":{"enum":["xref.code.add","xref.code.delete","xref.data.add","xref.data.delete"]}},"required":["kind"]},"then":{"properties":{"value":` + addressSchema + `}}},
    {"if":{"properties":{"kind":{"enum":["xref.code.add","xref.code.delete"]}},"required":["kind"]},"then":{"properties":{"subject":{"enum":["call_far","call_near","jump_far","jump_near"]}}}},
    {"if":{"properties":{"kind":{"enum":["xref.data.add","xref.data.delete"]}},"required":["kind"]},"then":{"properties":{"subject":{"enum":["offset","write","read","text","informational"]}}}},
    {"if":{"properties":{"kind":{"const":"function.flags"}},"required":["kind"]},"then":{"properties":{"value":{"pattern":"^(?:noreturn|library|static|hidden|thunk)(?:,(?:noreturn|library|static|hidden|thunk))*$|^$"}}}},
    {"if":{"properties":{"kind":{"enum":["function.end","function.chunk.add","function.chunk.delete"]}},"required":["kind"]},"then":{"properties":{"value":` + addressSchema + `}}},
    {"if":{"properties":{"kind":{"enum":["function.chunk.add","function.chunk.delete"]}},"required":["kind"]},"then":{"properties":{"subject":` + addressSchema + `}}}
  ]
}`

const changesetPreviewInputSchema = `{
  "$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,
  "required":["operations"],"properties":{"instanceId":` + instanceIDSchema + `,"operations":{"type":"array","minItems":1,"maxItems":100,"items":` + changeOperationSchema + `}}
}`

const changesetApplyInputSchema = `{
  "$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,
  "required":["previewId","operations"],"properties":{"instanceId":` + instanceIDSchema + `,"previewId":{"type":"string","minLength":1,"maxLength":128},"operations":{"type":"array","minItems":1,"maxItems":100,"items":` + changeOperationSchema + `}}
}`

const changesetRollbackInputSchema = `{
  "$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,
  "required":["changeId"],"properties":{"instanceId":` + instanceIDSchema + `,"changeId":{"type":"string","minLength":1,"maxLength":256}}
}`

const changesetAuditInputSchema = `{
  "$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,
  "properties":{"instanceId":` + instanceIDSchema + `,"offset":{"type":"integer","minimum":0,"maximum":4294967295},"limit":{"type":"integer","minimum":1,"maximum":1000,"default":100}}
}`

const patchAssembleInputSchema = `{
  "$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,
  "required":["address","instruction"],"properties":{"instanceId":` + instanceIDSchema + `,"address":` + addressSchema + `,"instruction":{"type":"string","minLength":1,"maxLength":4096}}
}`

const patchWriteBytesInputSchema = `{
  "$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,
  "required":["address","bytes"],"properties":{"instanceId":` + instanceIDSchema + `,"address":` + addressSchema + `,"bytes":{"type":"string","description":"Even-length hexadecimal bytes to write.","minLength":2,"maxLength":65536,"pattern":"^(?:[0-9A-Fa-f]{2})+$"},"expectedBytes":{"type":"string","description":"Optional hexadecimal current bytes used as a conflict guard.","minLength":2,"maxLength":65536,"pattern":"^(?:[0-9A-Fa-f]{2})+$"}}
}`

const patchWriteIntegerInputSchema = `{
  "$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,
  "required":["address","value","integerType"],"properties":{"instanceId":` + instanceIDSchema + `,"address":` + addressSchema + `,"value":{"type":"string","description":"Integer literal in decimal or 0x, 0b, or 0o notation.","minLength":1,"maxLength":67,"pattern":"^[+-]?(?:0[xX][0-9A-Fa-f]+|0[bB][01]+|0[oO][0-7]+|[0-9]+)$"},"integerType":{"type":"string","description":"Signedness, width, and explicit byte order.","enum":["u8","i8","u16le","i16le","u16be","i16be","u32le","i32le","u32be","i32be","u64le","i64le","u64be","i64be"]},"expectedBytes":{"type":"string","description":"Optional hexadecimal current bytes used as a conflict guard.","minLength":2,"maxLength":16,"pattern":"^(?:[0-9A-Fa-f]{2})+$"}}
}`

const diffBeforeAfterInputSchema = `{
  "$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,
  "required":["action"],"properties":{"instanceId":` + instanceIDSchema + `,"action":{"allOf":[` + changeOperationSchema + `,{"required":["address"]}]}}
}`
