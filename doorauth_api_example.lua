-- doorauth_api_example.lua
-- Loadable library for scripting the DoorAuth admin API:
--   os.loadAPI("doorauth_api_example.lua")
--   local session = doorauth_api_example.login("1234")
--   local result  = doorauth_api_example.listUsers(session)
--
-- Every call auto-renews the session (re-logs in with the stored PIN) once
-- if the server reports the token has expired.

os.loadAPI("config_util.lua")

config = {
  protocol        = "doorAuth.v1",
  server_name     = "DoorAuthServer",
  request_timeout = 3,
}

local function request(payload, c)
  c = c or config
  config_util.openModems()
  local server = config_util.findServer(c.protocol, c.server_name)
  if not server then return nil, "Server offline." end

  rednet.send(server, payload, c.protocol)
  local id, msg = rednet.receive(c.protocol, c.request_timeout)
  if id ~= server then return nil, "No response." end
  return msg
end

-- login(adminPin, config?) -> session, err
function login(adminPin, c)
  c = c or config
  local challengeMsg, err = request({type="admin_login_challenge"}, c)
  if not challengeMsg or challengeMsg.type ~= "admin_login_challenge_salt" then
    return nil, err or "No challenge response."
  end

  local stamp = tostring(os.epoch("utc"))
  local sig = config_util.hash(config_util.hash(adminPin, challengeMsg.salt)..stamp, "")

  local msg, err2 = request({type="admin_login", timestamp=stamp, sig=sig}, c)
  if msg and msg.type == "admin_login_ok" then
    return {
      token      = msg.token,
      pin        = adminPin,
      protocol   = c.protocol,
      serverName = c.server_name,
      loginAt    = os.epoch("utc"),
    }
  end
  return nil, (msg and msg.reason) or err2 or "Login failed."
end

-- call(session, cmd, payload?, config?) -> response message
-- Auto-relogs in once (using session.pin) if the server says the token
-- has expired, then retries the same call.
function call(session, command, payload, c)
  c = c or config
  payload = payload or {}
  payload.cmd = command
  payload.type = "admin_cmd"
  payload.token = session.token

  local msg = request(payload, c)
  if msg and msg.type == "admin_denied" then
    local newSession, err = login(session.pin, c)
    if not newSession then return nil, err end
    session.token = newSession.token
    session.loginAt = newSession.loginAt
    payload.token = session.token
    msg = request(payload, c)
  end
  return msg
end

----------------------------------------------------------------
-- Door verbs
----------------------------------------------------------------
function listDoors(session, c) return call(session, "list", {}, c) end
function showDoor(session, tag, c) return call(session, "show", {tag=tag}, c) end
function addPin(session, tag, pin, c) return call(session, "add", {tag=tag, pin=pin}, c) end
function removePin(session, tag, pin, c) return call(session, "del", {tag=tag, pin=pin}, c) end
function setDoorOpenTime(session, tag, seconds, c) return call(session, "opentime", {tag=tag, seconds=seconds}, c) end
function remoteOpen(session, tag, c) return call(session, "open", {tag=tag}, c) end

----------------------------------------------------------------
-- User verbs
----------------------------------------------------------------
function listUsers(session, c) return call(session, "user_list", {}, c) end
function searchUsers(session, query, c) return call(session, "user_search", {query=query}, c) end
function showUser(session, name, c) return call(session, "user_show", {name=name}, c) end
function addUser(session, name, code, c) return call(session, "user_add", {name=name, code=code}, c) end
function clearUserCode(session, name, c) return call(session, "user_clear_code", {name=name}, c) end
function clearUserDoors(session, name, c) return call(session, "user_clear_doors", {name=name}, c) end
function cloneUserAccess(session, sourceName, targetName, includeCode, c)
  return call(session, "user_clone", {source=sourceName, name=targetName, includeCode=includeCode}, c)
end
function enableDoorForUser(session, name, tag, c) return call(session, "user_enable", {name=name, tag=tag}, c) end
function disableDoorForUser(session, name, tag, c) return call(session, "user_disable", {name=name, tag=tag}, c) end
function removeUser(session, name, c) return call(session, "user_del", {name=name}, c) end

-- issueCard returns the raw token string as a second value for convenience.
function issueCard(session, name, c)
  local msg = call(session, "user_card_issue", {name=name}, c)
  return msg, msg and msg.token
end
function clearCard(session, name, c) return call(session, "user_card_clear", {name=name}, c) end

----------------------------------------------------------------
-- Security verbs
----------------------------------------------------------------
function lockdown(session, enabled, c)
  return call(session, enabled and "lockdown_on" or "lockdown_off", {}, c)
end
function viewLogs(session, c) return call(session, "logs", {}, c) end

----------------------------------------------------------------
-- Usage banner if run directly instead of os.loadAPI'd
----------------------------------------------------------------
local function runningDirectly()
  local ok, prog = pcall(shell.getRunningProgram)
  return ok and prog and prog:match("doorauth_api_example%.lua$") ~= nil
end

if runningDirectly() then
  print([[doorauth_api_example.lua is a library, not a program.

Load it from your own script with:
  os.loadAPI("doorauth_api_example.lua")

Then, e.g.:
  local session = doorauth_api_example.login("1234")
  local users    = doorauth_api_example.listUsers(session)
  local ok, tok  = doorauth_api_example.issueCard(session, "alice")
]])
end
