package mcpserver

const databaseEntryPointsInputSchema = `{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "type":"object","additionalProperties":false,
  "properties":{
    "instanceId":` + instanceIDSchema + `,
    "name":{"type":"string","maxLength":256},
    "type":{"type":"string","enum":["entry","export"]},
    "limit":{"type":"integer","minimum":1,"maximum":100,"default":20},
    "cursor":{"type":"string","pattern":"^ep2\\.[A-Za-z0-9_-]{72}\\.[A-Za-z0-9_-]{43}$"}
  }
}`

const symbolExportsInputSchema = `{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "type":"object","additionalProperties":false,
  "properties":{
    "instanceId":` + instanceIDSchema + `,
    "name":{"type":"string","maxLength":256},
    "limit":{"type":"integer","minimum":1,"maximum":100,"default":20},
    "cursor":{"type":"string","pattern":"^se2\\.[A-Za-z0-9_-]{72}\\.[A-Za-z0-9_-]{43}$"}
  }
}`

const symbolSearchInputSchema = `{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "type":"object","additionalProperties":false,
  "properties":{
    "instanceId":` + instanceIDSchema + `,
    "name":{"type":"string","maxLength":256},
    "kind":{"type":"string","enum":["global","data","label"]},
    "limit":{"type":"integer","minimum":1,"maximum":100,"default":20},
    "cursor":{"type":"string","pattern":"^sy2\\.[A-Za-z0-9_-]{72}\\.[A-Za-z0-9_-]{43}$"}
  }
}`
