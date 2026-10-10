package mcpserver

const memorySearchBytesInputSchema = `{
  "$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,"required":["pattern","start","end"],
  "properties":{"instanceId":` + instanceIDSchema + `,"pattern":{"type":"string","minLength":1,"maxLength":1024},"start":` + addressSchema + `,"end":` + addressSchema + `,"limit":{"type":"integer","minimum":1,"maximum":100,"default":20}}
}`

const instructionSearchInputSchema = `{
  "$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,"required":["start","end"],
  "properties":{"instanceId":` + instanceIDSchema + `,"start":` + addressSchema + `,"end":` + addressSchema + `,"mnemonic":{"type":"string","maxLength":256},"operand":{"type":"string","maxLength":256},"limit":{"type":"integer","minimum":1,"maximum":100,"default":20},"cursor":{"type":"string","minLength":50,"maxLength":2048,"pattern":"^in2\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]{43}$"}}
}`

const listingSearchInputSchema = `{
  "$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,"required":["start","end","query"],
  "properties":{"instanceId":` + instanceIDSchema + `,"start":` + addressSchema + `,"end":` + addressSchema + `,"query":{"type":"string","minLength":1,"maxLength":1024},"limit":{"type":"integer","minimum":1,"maximum":100,"default":20}}
}`

const listingSearchTextInputSchema = `{
  "$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,"required":["start","end"],
  "oneOf":[{"required":["query"],"not":{"required":["regex"]}},{"required":["regex"],"not":{"required":["query"]}}],
  "properties":{"instanceId":` + instanceIDSchema + `,"start":` + addressSchema + `,"end":` + addressSchema + `,"query":{"type":"string","minLength":1,"maxLength":1024},"regex":{"type":"string","minLength":1,"maxLength":256},"includeDisassembly":{"type":"boolean","default":true},"includeComments":{"type":"boolean","default":true},"limit":{"type":"integer","minimum":1,"maximum":100,"default":20},"cursor":{"type":"string","minLength":50,"maxLength":2048,"pattern":"^lt2\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]{43}$"}}
}`

const stringSearchRegexInputSchema = `{
  "$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,
  "not":{"required":["refresh","cursor"],"properties":{"refresh":{"const":true}}},"required":["pattern"],
  "properties":{
    "refresh":{"type":"boolean","default":false,"description":"Reuse the existing IDA string list by default. Set true to rebuild it before the first page; cannot be combined with cursor. A rebuild may be slow, especially while debugging."},"instanceId":` + instanceIDSchema + `,"pattern":{"type":"string","minLength":1,"maxLength":1024},"minLength":{"type":"integer","minimum":1,"maximum":4096,"default":4},"limit":{"type":"integer","minimum":1,"maximum":100,"default":20},"cursor":{"type":"string","minLength":50,"maxLength":2048,"pattern":"^sr2\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]{43}$"}}
}`

const signatureMakeInputSchema = `{
  "$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,
  "oneOf":[{"required":["address"],"not":{"anyOf":[{"required":["start"]},{"required":["end"]}]}},{"required":["mode","start","end"],"properties":{"mode":{"const":"range"}},"not":{"required":["address"]}}],
  "properties":{"instanceId":` + instanceIDSchema + `,"mode":{"type":"string","enum":["address","function","range"],"default":"address"},"address":` + addressSchema + `,"start":` + addressSchema + `,"end":` + addressSchema + `,"format":{"type":"string","enum":["ida","x64dbg","mask","bitmask"],"default":"ida"},"wildcardOperands":{"type":"boolean","default":true},"maxLength":{"type":"integer","minimum":1,"maximum":1000,"default":1000}}
}`

const signatureXrefsInputSchema = `{
  "$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,"required":["address"],
  "properties":{"instanceId":` + instanceIDSchema + `,"address":` + addressSchema + `,"format":{"type":"string","enum":["ida","x64dbg","mask","bitmask"],"default":"ida"},"wildcardOperands":{"type":"boolean","default":true},"maxLength":{"type":"integer","minimum":1,"maximum":1000,"default":250},"top":{"type":"integer","minimum":1,"maximum":32,"default":5}}
}`

const structFieldXrefsInputSchema = `{
  "$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,"required":["type","field"],
  "properties":{"instanceId":` + instanceIDSchema + `,"type":{"type":"string","minLength":1,"maxLength":1024},"field":{"type":"string","minLength":1,"maxLength":1024},"limit":{"type":"integer","minimum":1,"maximum":1000,"default":100}}
}`
