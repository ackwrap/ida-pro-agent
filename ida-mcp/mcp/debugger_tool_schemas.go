package mcpserver

const debuggerEmptyInputSchema = `{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,"properties":{"instanceId":` + instanceIDSchema + `}}`

const debuggerControlInputSchema = `{
  "$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,"required":["action"],
  "properties":{"instanceId":` + instanceIDSchema + `,"action":{"type":"string","enum":["continue","step_into","step_over","step_until_return","run_to"]},"address":` + addressSchema + `},
  "allOf":[{"if":{"properties":{"action":{"const":"run_to"}}},"then":{"required":["address"]},"else":{"not":{"required":["address"]}}}]
}`

const debuggerBreakpointsInputSchema = `{
  "$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,
  "properties":{"instanceId":` + instanceIDSchema + `,"action":{"type":"string","enum":["add","delete","toggle","condition"]},"address":` + addressSchema + `,"enabled":{"type":"boolean"},"condition":{"type":["string","null"],"maxLength":4096},"type":{"type":"string","enum":["software","hardware"]},"size":{"type":"integer","minimum":0,"maximum":8},"language":{"type":"string","minLength":1,"maxLength":128},"lowLevel":{"type":"boolean"},"passCount":{"type":"integer","minimum":0,"maximum":2147483647}},
  "oneOf":[
    {"not":{"anyOf":[{"required":["action"]},{"required":["address"]},{"required":["enabled"]},{"required":["condition"]},{"required":["type"]},{"required":["size"]},{"required":["language"]},{"required":["lowLevel"]},{"required":["passCount"]}]}},
    {"properties":{"action":{"const":"add"}},"required":["action","address"]},
    {"properties":{"action":{"const":"delete"}},"required":["action","address"],"not":{"anyOf":[{"required":["enabled"]},{"required":["condition"]},{"required":["type"]},{"required":["size"]},{"required":["language"]},{"required":["lowLevel"]},{"required":["passCount"]}]}},
    {"properties":{"action":{"const":"toggle"}},"required":["action","address","enabled"],"not":{"anyOf":[{"required":["condition"]},{"required":["type"]},{"required":["size"]},{"required":["language"]},{"required":["lowLevel"]},{"required":["passCount"]}]}},
    {"properties":{"action":{"const":"condition"}},"required":["action","address"],"anyOf":[{"required":["condition"]},{"required":["language"]},{"required":["lowLevel"]},{"required":["passCount"]}],"not":{"anyOf":[{"required":["enabled"]},{"required":["type"]},{"required":["size"]}]}}
  ]
}`

const debuggerRegistersInputSchema = `{
  "$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,
  "properties":{"instanceId":` + instanceIDSchema + `,"threadMode":{"type":"string","enum":["current","specified","all"]},"threadIds":{"type":"array","minItems":1,"maxItems":256,"uniqueItems":true,"items":{"type":"integer","minimum":1,"maximum":9223372036854775807}},"registerMode":{"type":"string","enum":["all","named","general-purpose"]},"names":{"type":"array","minItems":1,"maxItems":256,"uniqueItems":true,"items":{"type":"string","minLength":1,"maxLength":128}}},
  "allOf":[{"if":{"required":["threadIds"]},"then":{"properties":{"threadMode":{"const":"specified"}}}},{"if":{"properties":{"threadMode":{"const":"specified"}},"required":["threadMode"]},"then":{"required":["threadIds"]},"else":{"not":{"allOf":[{"required":["threadMode"]},{"required":["threadIds"]}]}}},{"if":{"required":["names"]},"then":{"properties":{"registerMode":{"const":"named"}}}},{"if":{"properties":{"registerMode":{"const":"named"}},"required":["registerMode"]},"then":{"required":["names"]},"else":{"not":{"allOf":[{"required":["registerMode"]},{"required":["names"]}]}}}]
}`

const debuggerStackTraceInputSchema = `{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,"properties":{"instanceId":` + instanceIDSchema + `,"threadId":{"type":"integer","minimum":1,"maximum":9223372036854775807},"limit":{"type":"integer","minimum":1,"maximum":1000,"default":100}}}`
const debuggerMemoryReadInputSchema = `{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,"required":["address","length"],"properties":{"instanceId":` + instanceIDSchema + `,"address":` + addressSchema + `,"length":{"type":"integer","minimum":1,"maximum":65536}}}`
const debuggerMemoryWriteInputSchema = `{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,"required":["address","bytes"],"properties":{"instanceId":` + instanceIDSchema + `,"address":` + addressSchema + `,"bytes":{"type":"string","minLength":2,"maxLength":131072,"pattern":"^(?:[0-9A-Fa-f]{2})+$"}}}`
