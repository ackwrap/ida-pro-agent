package mcpserver

const catalogInstanceInputSchema = `{
  "$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,
  "properties":{"instanceId":` + instanceIDSchema + `}
}`

const databaseSurveyInputSchema = `{
  "$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,
  "properties":{"instanceId":` + instanceIDSchema + `,"mode":{"type":"string","enum":["full","minimal"],"default":"full"},"budget":{"type":"integer","minimum":3,"maximum":100,"default":60}}
}`

const databaseSaveInputSchema = `{
  "$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,
  "properties":{"instanceId":` + instanceIDSchema + `,"compact":{"type":"boolean","default":false},"backup":{"type":"boolean","default":false}}
}`

const functionCallersInputSchema = `{
  "$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,"required":["address"],
  "properties":{"instanceId":` + instanceIDSchema + `,"address":` + addressSchema + `,"offset":{"type":"integer","minimum":0,"maximum":1000000,"default":0},"limit":{"type":"integer","minimum":1,"maximum":100,"default":20}}
}`

const functionCallGraphInputSchema = `{
  "$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,"required":["roots"],
  "properties":{"instanceId":` + instanceIDSchema + `,"roots":{"type":"array","minItems":1,"maxItems":16,"items":` + addressSchema + `},"direction":{"type":"string","enum":["callers","callees","both"],"default":"callees"},"maxDepth":{"type":"integer","minimum":0,"maximum":5,"default":2},"maxNodes":{"type":"integer","minimum":1,"maximum":500,"default":100},"maxEdges":{"type":"integer","minimum":1,"maximum":1000,"default":200},"perFunction":{"type":"integer","minimum":1,"maximum":100,"default":100}}
}`

const functionProfileInputSchema = `{
  "$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,
  "properties":{"instanceId":` + instanceIDSchema + `,"name":{"type":"string","maxLength":1024},"minSize":{"type":"integer","minimum":0,"maximum":1048576,"default":0},"maxSize":{"type":"integer","minimum":1,"maximum":1048576,"default":1048576},"library":{"type":"boolean"},"thunk":{"type":"boolean"},"includePrototype":{"type":"boolean","default":false},"sampleLimit":{"type":"integer","minimum":0,"maximum":8,"default":0},"limit":{"type":"integer","minimum":1,"maximum":50,"default":20},"cursor":{"type":"string","minLength":50,"maxLength":2048,"pattern":"^fp2\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]{43}$"}}
}`

const functionExportInputSchema = `{
  "$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,"required":["addresses","format"],
  "properties":{"instanceId":` + instanceIDSchema + `,"addresses":{"type":"array","minItems":1,"maxItems":100,"items":` + addressSchema + `},"format":{"type":"string","enum":["json","c_header","prototypes"]},"maxBytes":{"type":"integer","minimum":1024,"maximum":65536,"default":32768}}
}`

const functionAnalyzeInputSchema = `{
  "$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,"required":["addresses"],
  "properties":{"instanceId":` + instanceIDSchema + `,"addresses":{"type":"array","minItems":1,"maxItems":8,"items":` + addressSchema + `},"sections":{"type":"array","minItems":1,"maxItems":11,"uniqueItems":true,"items":{"type":"string","enum":["overview","metrics","prototype","callers","callees","blocks","xrefs","strings","constants","comments","decompile"]}},"perSection":{"type":"integer","minimum":1,"maximum":100,"default":50},"decompileBytes":{"type":"integer","minimum":1024,"maximum":65536,"default":16384}}
}`

const functionStackFrameInputSchema = functionAddressInputSchema
