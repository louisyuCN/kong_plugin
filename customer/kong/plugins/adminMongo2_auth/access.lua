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

    local connection_name = "tel"
    local request_url = kong.request.get_path()

    if (request_url == "/mongo/app" or request_url == "/mongo/app/"..connection_name)  then 
        return ngx.redirect("/mongo/app/"..connection_name.."/"..given_username) 
    end

    if request_url == "/mongo/app/"..connection_name.."/admin" then
        return ngx.redirect("/mongo/app/"..connection_name.."/runsa")
    end

    local _,_,usercode = string.find(request_url, "/mongo/app/"..connection_name.. "/([0-9a-zA-Z]+).*")

    if usercode == nil 
    then
        return true
    elseif given_username == "runsa" then
        return true
    elseif usercode ~= given_username then
        return false, { status = 403, message = "Permission denied!" }
  end

  function _M.execute(conf)
    local ok, err = do_authentication(conf)
    if not ok then
        return kong.response.exit(err.status, { message = err.message }, err.headers)
        end
     end
  end

  return _M