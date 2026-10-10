package mcpserver

const instanceIDSchema = `{"type":"string","pattern":"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"}`
const addressSchema = `{"type":"string","pattern":"^0x[0-9A-Fa-f]{1,16}$"}`

const instancesListInputSchema = `{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "type":"object","additionalProperties":false
}`

const instanceSelectInputSchema = `{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "type":"object","additionalProperties":false,"required":["instanceId"],
  "properties":{"instanceId":` + instanceIDSchema + `}
}`

const instancesGetActiveInputSchema = instancesListInputSchema

const instanceInputSchema = `{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "type":"object","additionalProperties":false,
  "properties":{"instanceId":` + instanceIDSchema + `}
}`

const functionAddressInputSchema = `{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "type":"object","additionalProperties":false,"required":["address"],
  "properties":{"instanceId":` + instanceIDSchema + `,"address":` + addressSchema + `}
}`

const functionSearchInputSchema = `{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "type":"object","additionalProperties":false,
  "properties":{
    "instanceId":` + instanceIDSchema + `,
    "name":{"type":"string","maxLength":256},
    "address":` + addressSchema + `,
    "limit":{"type":"integer","minimum":1,"maximum":100,"default":20},
    "cursor":{"type":"string","pattern":"^fs2\\.[A-Za-z0-9_-]{72}\\.[A-Za-z0-9_-]{43}$"}
  },
  "oneOf":[
    {"required":["name"],"not":{"required":["address"]}},
    {"required":["address"],"not":{"anyOf":[{"required":["name"]},{"required":["cursor"]}]}}
  ]
}`

const xrefQueryInputSchema = `{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "type":"object","additionalProperties":false,"required":["address","direction"],
  "properties":{
    "instanceId":` + instanceIDSchema + `,"address":` + addressSchema + `,
    "direction":{"type":"string","enum":["incoming","outgoing"]},
    "category":{"type":"string","enum":["all","code","data"],"default":"all"},
    "includeFlow":{"type":"boolean","default":false},
    "limit":{"type":"integer","minimum":1,"maximum":100,"default":20},
    "cursor":{"type":"string","pattern":"^xq3\\.[A-Za-z0-9_-]{72}\\.[A-Za-z0-9_-]{43}$"}
  }
}`

const memoryReadInputSchema = `{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "type":"object","additionalProperties":false,"required":["address","format"],
  "properties":{
    "instanceId":` + instanceIDSchema + `,"address":` + addressSchema + `,
    "format":{"type":"string","enum":["bytes","string","integer","pointer"]},
    "length":{"type":"integer","minimum":1,"maximum":4096},
    "widthBits":{"type":"integer","enum":[8,16,32,64]}
  },
  "oneOf":[
    {"properties":{"format":{"const":"bytes"}},"required":["length"],"not":{"required":["widthBits"]}},
    {"properties":{"format":{"const":"string"}},"required":["length"],"not":{"required":["widthBits"]}},
    {"properties":{"format":{"const":"integer"}},"required":["widthBits"],"not":{"required":["length"]}},
    {"properties":{"format":{"const":"pointer"}},"not":{"anyOf":[{"required":["length"]},{"required":["widthBits"]}]}}
  ]
}`

const decompileInputSchema = `{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "type":"object","additionalProperties":false,"required":["address"],
  "properties":{
    "instanceId":` + instanceIDSchema + `,"address":` + addressSchema + `,
    "offset":{"type":"integer","minimum":0,"maximum":16777216,"default":0},
    "maxBytes":{"type":"integer","minimum":4,"maximum":65536,"default":32768}
  }
}`
