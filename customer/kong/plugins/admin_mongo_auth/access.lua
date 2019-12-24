local constants = require "kong.constants"
local decode_base64 = ngx.decode_base64
local re_gmatch = ngx.re.gmatch
local re_match = ngx.re.match
local kong = kong

local _M = {}


-- Fast lookup for credential retrieval depending on the type of the authentication
--
-- All methods must respect:
--
-- @param request ngx request object
-- @param {table} conf Plugin config
-- @return {string} public_key
-- @return {string} private_key
local function retrieve_credentials(header_name, conf)

  -- If both headers are missing, return 401
  if not (kong.request.get_header("authorization") or kong.request.get_header("proxy-authorization")) then
    return false, {
      status = 401,
      message = "Unauthorized",
      headers = {
        ["WWW-Authenticate"] = realm
      }
    }
  end

  local username, password
  local authorization_header = kong.request.get_header(header_name)

  if authorization_header then
    local iterator, iter_err = re_gmatch(authorization_header, "\\s*[Bb]asic\\s*(.+)")
    if not iterator then
      kong.log.err(iter_err)
      return
    end

    local m, err = iterator()
    if err then
      kong.log.err(err)
      return
    end

    if m and m[1] then
      local decoded_basic = decode_base64(m[1])
      if decoded_basic then
        local basic_parts, err = re_match(decoded_basic, "([^:]+):(.*)", "oj")
        if err then
          kong.log.err(err)
          return
        end

        if not basic_parts then
          kong.log.err("header has unrecognized format")
          return
        end

        username = basic_parts[1]
        password = basic_parts[2]
        
      end
    end
  end

  if conf.hide_credentials then
    kong.service.request.clear_header(header_name)
  end

  return username, password
end

local function do_authentication(conf)
  local given_username, given_password = retrieve_credentials("proxy-authorization", conf)

  if not given_username then
    given_username, given_password = retrieve_credentials("authorization", conf)
  end

  local default_conn = "tel"
  local request_url = kong.request.get_path()
  local m1 = string.match(request_url, "/[0-9a-zA-Z]+/app/[0-9a-zA-Z]+")
  
  if m1 then
    return ngx.redirect(m1..default_conn..given_username)
  end

  local m2 = string.match(request_url, "/[0-9a-zA-Z]+/app/[0-9a-zA-Z]+/[0-9a-zA-Z]+")

  if m2 then
    return ngx.redirect(m2..given_username)
  end

  local m3 = string.match(request_url, "/[0-9a-zA-Z]+/app/[0-9a-zA-Z]+/admin")

  if m3 then
    return ngx.redirect(request_url, (string.sub(m3, 0, -6)) .. "runsa")
  end

  local m4 = string.match(request_url, "/[0-9a-zA-Z]+/app/[0-9a-zA-Z]+/[0-9a-zA-Z]+")
  
  if m4 ~= nil  then
    local _, _, usercode = string.find(request_url, "/[0-9a-zA-Z]+/app/[0-9a-zA-Z]+/([0-9a-zA-Z]+)")
    
    if given_username == "runsa" then
      return true
    elseif usercode ~= given_username then
      return false, { status = 403, message = "Permission denied!" }
    end

  end 
  return true
end

function _M.execute(conf)
  local ok, err = do_authentication(conf)

  if not ok then
      return kong.response.exit(err.status, { message = err.message }, err.headers)
  end
end

return _M