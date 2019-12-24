-- Copyright (C) Kong Inc.
local BasePlugin = require "kong.plugins.base_plugin"
local access = require "kong.plugins.adminMongo_auth2.access"


local BasicAuthHandler = BasePlugin:extend()


function BasicAuthHandler:new()
  BasicAuthHandler.super.new(self, "adminMongo_auth2")
end


function BasicAuthHandler:access(conf)
  BasicAuthHandler.super.access(self)
  access.execute(conf)
end


BasicAuthHandler.PRIORITY = 1000
BasicAuthHandler.VERSION = "1.0.0"


return BasicAuthHandler