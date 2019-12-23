-- Copyright (C) Kong Inc.
local BasePlugin = require "kong.plugins.base_plugin"
local access = require "kong.plugins.adminMongo_auth.access"


local BasicAuthHandler = BasePlugin:extend()


function BasicAuthHandler:new()
  BasicAuthHandler.super.new(self, "adminMongo_auth")
end


function BasicAuthHandler:access(conf)
  BasicAuthHandler.super.access(self)
  access.execute(conf)
end


BasicAuthHandler.PRIORITY = 1001
BasicAuthHandler.VERSION = "1.0.0"


return BasicAuthHandler
