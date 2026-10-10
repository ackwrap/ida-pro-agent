package mcpserver

const globalValueInputSchema = `{
  "$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,"oneOf":[{"required":["address"],"not":{"required":["name"]}},{"required":["name"],"not":{"required":["address"]}}],
  "properties":{"instanceId":` + instanceIDSchema + `,"address":` + addressSchema + `,"name":{"type":"string","minLength":1,"maxLength":1024},"maxBytes":{"type":"integer","minimum":1,"maximum":65536,"default":4096}}
}`
const typeSearchInputSchema = `{
  "$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,
  "properties":{"instanceId":` + instanceIDSchema + `,"name":{"type":"string","maxLength":1024},"kind":{"type":"string","enum":["any","typedef","enum","function","pointer","array","udt","struct","union","other"],"default":"any"},"ordinal":{"type":"integer","minimum":1,"maximum":1000000,"default":1},"limit":{"type":"integer","minimum":1,"maximum":100,"default":20}}
}`
const typeGetInputSchema = `{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,"required":["name"],"properties":{"instanceId":` + instanceIDSchema + `,"name":{"type":"string","minLength":1,"maxLength":1024}}}`
const typeReadValueInputSchema = `{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,"required":["address","name"],"properties":{"instanceId":` + instanceIDSchema + `,"address":` + addressSchema + `,"name":{"type":"string","minLength":1,"maxLength":1024},"maxBytes":{"type":"integer","minimum":1,"maximum":65536,"default":4096}}}`
const typeReadStructInputSchema = `{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,"required":["address"],"properties":{"instanceId":` + instanceIDSchema + `,"address":` + addressSchema + `,"name":{"type":"string","maxLength":1024},"maxBytes":{"type":"integer","minimum":1,"maximum":65536,"default":4096}}}`
const typeInferInputSchema = `{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,"required":["address"],"properties":{"instanceId":` + instanceIDSchema + `,"address":` + addressSchema + `}}`
const analysisComponentInputSchema = `{
  "$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,"required":["roots"],
  "properties":{"instanceId":` + instanceIDSchema + `,"roots":{"type":"array","minItems":1,"maxItems":16,"uniqueItems":true,"items":` + addressSchema + `},"maxDepth":{"type":"integer","minimum":0,"maximum":5,"default":2},"maxNodes":{"type":"integer","minimum":1,"maximum":200,"default":100},"maxEdges":{"type":"integer","minimum":1,"maximum":1000,"default":200},"perFunction":{"type":"integer","minimum":1,"maximum":100,"default":50},"sharedLimit":{"type":"integer","minimum":1,"maximum":100,"default":100}}
}`
const traceDataFlowInputSchema = `{
  "$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,"required":["address"],
  "properties":{"instanceId":` + instanceIDSchema + `,"address":` + addressSchema + `,"direction":{"type":"string","enum":["incoming","outgoing","both"],"default":"both"},"maxDepth":{"type":"integer","minimum":0,"maximum":8,"default":3},"maxNodes":{"type":"integer","minimum":1,"maximum":1000,"default":200},"maxEdges":{"type":"integer","minimum":1,"maximum":2000,"default":500}}
}`
