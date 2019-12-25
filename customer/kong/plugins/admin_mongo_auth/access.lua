local constants = require "kong.constants"
local decode_base64 = ngx.decode_base64
local re_gmatch = ngx.re.gmatch
local re_match = ngx.re.match
local kong = kong

local _M = {}

-- 获取账号密码 --
local function retrieve_credentials(header_name, conf)

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

-- 验证权限 --
local function do_authentication(conf)
  local given_username, given_password = retrieve_credentials("proxy-authorization", conf)

  if not given_username then
    given_username, given_password = retrieve_credentials("authorization", conf)
  end

  local request_url = kong.request.get_path()
  local m1 = string.match(request_url, "^/app/[0-9a-zA-Z]+$")
  
  -- /app/runsaec 转发 -> /app/runsaec/given_username --
  if m1 ~= nil then
    return ngx.redirect(m1 .. "/" ..given_username)
  end

  local m2 = string.match(request_url, "^/app/[0-9a-zA-Z]+/admin$")

  -- /app/runsaec/admin 转发 -> /app/runsaec/runsa --
  if m2 ~= nil then
    return ngx.redirect((string.sub(m2, 0, -6)) .. "runsa")
  end

  local m3 = string.match(request_url, "^/app/[0-9a-zA-Z]+/[0-9a-zA-Z]+.*$")
  local m4 = string.match(request_url, "^/api/[0-9a-zA-Z]+/[0-9a-zA-Z]+.*$")
  
  -- 登录的账号和url中的客户号比较 --
  if m3 ~= nil then
    local _, _, usercode = string.find(request_url, "/app/[0-9a-zA-Z]+/([0-9a-zA-Z]+)")
    return checkUsercode(usercode, given_username)
  elseif m4 ~= nil then 
    local _, _, usercode = string.find(request_url, "/api/[0-9a-zA-Z]+/([0-9a-zA-Z]+)")
    return checkUsercode(usercode, given_password)
  else 
    return true
  end 
end

local function checkUsercode(usercode, given_username)
  if given_username == "runsa" then
    return true
  elseif usercode ~= given_username then
    return false, { status = 403, message = "Permission denied!" }
  else 
    return true
  end
end

-- export --
function _M.execute(conf)
  local ok, err = do_authentication(conf)

  if not ok then
      return kong.response.exit(err.status, { message = err.message }, err.headers)
  end
end

return _M