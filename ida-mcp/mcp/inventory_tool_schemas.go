package mcpserver

const databaseSegmentsInputSchema = `{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "type":"object","additionalProperties":false,
  "properties":{
    "instanceId":` + instanceIDSchema + `,
    "name":{"type":"string","maxLength":256},
    "limit":{"type":"integer","minimum":1,"maximum":100,"default":20},
    "cursor":{"type":"string","pattern":"^ds2\\.[A-Za-z0-9_-]{72}\\.[A-Za-z0-9_-]{43}$"}
  }
}`

const stringSearchInputSchema = `{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "type":"object","additionalProperties":false,
  "not":{"required":["refresh","cursor"],"properties":{"refresh":{"const":true}}},
  "properties":{
    "refresh":{"type":"boolean","default":false,"description":"Reuse the existing IDA string list by default. Set true to rebuild it before the first page; cannot be combined with cursor. A rebuild may be slow, especially while debugging."},
    "instanceId":` + instanceIDSchema + `,
    "query":{"type":"string","maxLength":256},
    "minLength":{"type":"integer","minimum":1,"maximum":4096,"default":4},
    "limit":{"type":"integer","minimum":1,"maximum":100,"default":20},
    "cursor":{"type":"string","pattern":"^ss2\\.[A-Za-z0-9_-]{72}\\.[A-Za-z0-9_-]{43}$"}
  }
}`

const symbolImportsInputSchema = `{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "type":"object","additionalProperties":false,
  "properties":{
    "instanceId":` + instanceIDSchema + `,
    "module":{"type":"string","maxLength":256},
    "name":{"type":"string","maxLength":256},
    "limit":{"type":"integer","minimum":1,"maximum":100,"default":20},
    "cursor":{"type":"string","pattern":"^si2\\.[A-Za-z0-9_-]{72}\\.[A-Za-z0-9_-]{43}$"}
  }
}`
