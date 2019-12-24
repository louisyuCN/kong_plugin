local typedefs = require "kong.db.schema.typedefs"


return {
  name = "adminMongo_auth2",
  fields = {
    { consumer = typedefs.no_consumer },
    { run_on = typedefs.run_on_first },
    { config = {
        type = "record",
        fields = {
          { anonymous = { type = "string", uuid = true, legacy = true }, },
          { hide_credentials = { type = "boolean", default = false }, },
    }, }, },
  },
}
