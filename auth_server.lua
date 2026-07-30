--============================================================--
--  auth_server.lua
--  Features:
--    Admin PIN (salted hash) + local admin console
--    Remote admin (challenge/salt login, replay-protected, rate-limited)
--    Lockdown mode
--    Per-user accounts: hashed access codes + magnetic card tokens
--    Per-door PIN lists (salted hashes, legacy plaintext auto-migrated)
--    Failed-attempt lockout for door verification and admin login
--    Authenticated controller registration + signed open commands
--    Audit logs (persistent)
--    Heartbeat to controllers
--    Autosave + DB persistence
--============================================================--

os.loadAPI("config_util.lua")

------------------ Config ------------------
local defaults = {
  protocol              = "doorAuth.v1",
  open_event            = "doorAuth.open.v1",
  heartbeat_event       = "doorAuth.heartbeat.v1",
  host_name             = "DoorAuthServer",
  db_path               = "door_db.json",
  admin_path            = "admin.json",
  log_path              = "door_logs.json",
  save_interval         = 30,
  admin_timeout         = 120,
  heartbeat_rate        = 10,
  log_max               = 1000,
  registration_secret   = "change-me-registration-secret",
  verify_max_attempts   = 5,
  verify_window_sec     = 30,
  verify_lock_base_sec  = 5,
  verify_lock_max_sec   = 300,
  admin_max_attempts    = 5,
  admin_window_sec      = 60,
  admin_lock_base_sec   = 10,
  admin_lock_max_sec    = 600,
  admin_login_window_sec= 15,
  replay_ring_size      = 200,
}

local fields = {
  {key="protocol", label="Rednet protocol"},
  {key="open_event", label="Open event name"},
  {key="heartbeat_event", label="Heartbeat event name"},
  {key="host_name", label="Server host name"},
  {key="db_path", label="Door DB path"},
  {key="admin_path", label="Admin file path"},
  {key="log_path", label="Log file path"},
  {key="save_interval", label="Autosave interval (s)"},
  {key="admin_timeout", label="Admin session timeout (s)"},
  {key="heartbeat_rate", label="Heartbeat rate (s)"},
  {key="log_max", label="Max log entries"},
  {key="registration_secret", label="Controller registration secret",
    help="Every door_controller must send this to register. Change it from the default!"},
  {key="verify_max_attempts", label="Verify: attempts before lockout"},
  {key="verify_window_sec", label="Verify: attempt window (s)"},
  {key="verify_lock_base_sec", label="Verify: base lockout (s)"},
  {key="verify_lock_max_sec", label="Verify: max lockout (s)"},
  {key="admin_max_attempts", label="Admin login: attempts before lockout"},
  {key="admin_window_sec", label="Admin login: attempt window (s)"},
  {key="admin_lock_base_sec", label="Admin login: base lockout (s)"},
  {key="admin_lock_max_sec", label="Admin login: max lockout (s)"},
  {key="admin_login_window_sec", label="Admin login: signature freshness window (s)"},
  {key="replay_ring_size", label="Admin login: replay-cache size"},
}

local cfg = config_util.load("auth_server", defaults, fields, "DoorAuth Server Config")

local PROTOCOL               = cfg.protocol
local OPEN_EVENT              = cfg.open_event
local HEARTBEAT_EVENT          = cfg.heartbeat_event
local HOST_NAME               = cfg.host_name
local DB_PATH                 = cfg.db_path
local ADMIN_PATH              = cfg.admin_path
local LOG_PATH                = cfg.log_path
local SAVE_INTERVAL            = cfg.save_interval
local ADMIN_TIMEOUT            = cfg.admin_timeout
local HEARTBEAT_RATE            = cfg.heartbeat_rate
local LOG_MAX                  = cfg.log_max
local REGISTRATION_SECRET       = cfg.registration_secret
local VERIFY_MAX_ATTEMPTS       = cfg.verify_max_attempts
local VERIFY_WINDOW_SEC         = cfg.verify_window_sec
local VERIFY_LOCK_BASE_SEC      = cfg.verify_lock_base_sec
local VERIFY_LOCK_MAX_SEC       = cfg.verify_lock_max_sec
local ADMIN_MAX_ATTEMPTS        = cfg.admin_max_attempts
local ADMIN_WINDOW_SEC          = cfg.admin_window_sec
local ADMIN_LOCK_BASE_SEC       = cfg.admin_lock_base_sec
local ADMIN_LOCK_MAX_SEC        = cfg.admin_lock_max_sec
local ADMIN_LOGIN_WINDOW_SEC    = cfg.admin_login_window_sec
local REPLAY_RING_SIZE          = cfg.replay_ring_size
--------------------------------------------

------------------ Utils -------------------
local readAll      = config_util.readAll
local writeAll     = config_util.writeAll
local jsonEncode   = config_util.jsonEncode
local jsonDecode   = config_util.jsonDecode
local trim         = config_util.trim

local function now() return os.epoch("utc") end

local function clockString()
  local ok,t = pcall(os.time)
  if ok and textutils.formatTime then
    return textutils.formatTime(t, true)
  end
  return "??:??"
end
--------------------------------------------

------------------ State -------------------
local db = { doors = {}, users = {}, controllerKeys = {}, version = 2 }
local controllersByTag = {}
local cardTokenIndex = {} -- cardTokenHash -> user name
local lockdown = false
local logs = {}

local admin = {
  pinRecord   = nil, -- {salt=, hash=}
  cardPepper  = nil,
  loggedIn    = false,
  remoteToken = nil,
  lastAction  = 0
}

-- Rate limiting / lockout (in-memory only, per the project's stateless-client design)
local failCounters = {} -- key -> {count, firstFailAt, lockedUntil}

-- Admin login replay protection (in-memory ring buffer)
local seenStamps = {}
local seenOrder  = {}
--------------------------------------------

------------- Legacy hash (migration only) -------------
-- The old ("FINAL VERSION") server hashed the admin PIN with this trivial
-- rolling hash and stored the bare result string in admin.json. This is
-- ONLY used to verify an existing legacy file once, so it can be upgraded
-- to salted hashing - it must never be used for anything new.
local function legacySha256Migrate(str)
  local h = 0
  for i=1,#str do
    h=(h*31 + str:byte(i)) % 2^31
  end
  return tostring(h)
end
--------------------------------------------

------------------ Admin Auth --------------
local function saveAdmin()
  writeAll(ADMIN_PATH, jsonEncode({
    salt       = admin.pinRecord.salt,
    hash       = admin.pinRecord.hash,
    cardPepper = admin.cardPepper,
    version    = 2,
  }))
end

local function loadAdmin()
  local raw = readAll(ADMIN_PATH)

  if not raw then
    print("=== FIRST-TIME ADMIN SETUP ===")
    while true do
      write("New Admin PIN: ") local p1=read("*")
      write("Confirm PIN: ")   local p2=read("*")
      if p1==p2 and #p1>=4 then
        admin.pinRecord  = config_util.hashSecret(p1)
        admin.cardPepper = config_util.newToken("pepper")
        saveAdmin()
        print("Admin PIN saved.")
        break
      end
      print("Pins did not match or too short. Try again.")
    end
    return
  end

  local parsed = jsonDecode(raw)
  if type(parsed)=="table" and parsed.salt and parsed.hash then
    admin.pinRecord  = { salt = parsed.salt, hash = parsed.hash }
    admin.cardPepper = parsed.cardPepper
    if not admin.cardPepper then
      admin.cardPepper = config_util.newToken("pepper")
      saveAdmin()
    end
    return
  end

  -- Legacy bare-hash-string format detected.
  print("=== LEGACY ADMIN FILE DETECTED ===")
  print("Re-enter your admin PIN once to upgrade to salted hashing.")
  local legacyHash = trim(raw)
  while true do
    write("Current Admin PIN: ")
    local attempt = read("*")
    if legacySha256Migrate(attempt) == legacyHash then
      admin.pinRecord  = config_util.hashSecret(attempt)
      admin.cardPepper = config_util.newToken("pepper")
      saveAdmin()
      print("Admin PIN storage upgraded.")
      break
    end
    print("Incorrect PIN. Try again.")
  end
end

local function isAdminValid()
  if not admin.loggedIn then return false end
  if (now() - admin.lastAction) > ADMIN_TIMEOUT*1000 then
    admin.loggedIn = false
    admin.remoteToken = nil
    print("[ADMIN] Session expired.")
    return false
  end
  return true
end

local function requireAdmin()
  if isAdminValid() then
    admin.lastAction = now()
    return true
  end

  write("Admin PIN: ")
  local attempt = read("*")
  if config_util.checkSecret(attempt, admin.pinRecord) then
    admin.loggedIn   = true
    admin.lastAction = now()
    print("[ADMIN] Login OK")
    return true
  end

  print("[ADMIN] Incorrect PIN.")
  return false
end
--------------------------------------------

------------------ Rate limiting -----------
local function isLocked(key)
  local rec = failCounters[key]
  if not rec or not rec.lockedUntil then return false end
  if now() < rec.lockedUntil then return true end
  failCounters[key] = nil
  return false
end

local function noteFailure(key, maxAttempts, windowSec, baseSec, capSec)
  local rec = failCounters[key]
  local t = now()
  if not rec or (t - rec.firstFailAt) > windowSec*1000 then
    rec = { count = 0, firstFailAt = t }
    failCounters[key] = rec
  end
  rec.count = rec.count + 1
  if rec.count >= maxAttempts then
    local overBy = rec.count - maxAttempts
    local lockSec = math.min(baseSec * (2^overBy), capSec)
    rec.lockedUntil = t + lockSec*1000
  end
  return rec
end

local function noteSuccess(key)
  failCounters[key] = nil
end
--------------------------------------------

------------------ Logs ---------------------
local function loadLogs()
  local raw = readAll(LOG_PATH)
  if not raw then logs = {} return end
  local parsed = jsonDecode(raw)
  logs = type(parsed)=="table" and parsed or {}
end

local function saveLogs()
  writeAll(LOG_PATH, jsonEncode(logs))
end

local function logEvent(evt)
  local entry = {
    time   = clockString(),
    ts     = now(),
    event  = evt.event or "unknown",
    tag    = evt.tag,
    ok     = evt.ok,
    source = evt.source,
    detail = evt.detail
  }
  table.insert(logs, entry)
  if #logs > LOG_MAX then table.remove(logs,1) end
end
--------------------------------------------

------------- Persistence ------------------
local function ensureDBShape()
  db.doors          = db.doors or {}
  db.users          = db.users or {}
  db.controllerKeys = db.controllerKeys or {}
end

local function rebuildCardIndex()
  cardTokenIndex = {}
  for name, u in pairs(db.users) do
    if u.cardTokenHash then
      cardTokenIndex[u.cardTokenHash] = name
    end
  end
end

local function saveDB()
  writeAll(DB_PATH, jsonEncode(db))
  print("[DB] Saved.")
end

local function loadDB()
  local raw = readAll(DB_PATH)
  if raw then
    local parsed = jsonDecode(raw)
    if parsed and parsed.doors then
      db = parsed
      ensureDBShape()

      local migrated = false
      if not db.version or db.version < 2 then
        for _, door in pairs(db.doors) do
          local newPins = {}
          for _, p in ipairs(door.pins or {}) do
            if type(p) == "string" then
              table.insert(newPins, config_util.hashSecret(p))
              migrated = true
            else
              table.insert(newPins, p)
            end
          end
          door.pins = newPins
        end
        db.version = 2
      end

      rebuildCardIndex()
      print("[DB] Loaded.")
      if migrated then
        print("[DB] Migrated legacy plaintext door PINs to salted hashes.")
        logEvent({event="db_migration", ok=true, detail="pins_hashed"})
        saveDB()
      end
      return
    end
  end
  ensureDBShape()
  db.version = 2
  print("[DB] Starting fresh.")
end
--------------------------------------------

--------------- Networking -----------------
local openModems = config_util.openModems

local function broadcastOpen(tag, duration)
  local set = controllersByTag[tag]
  if not set then return end
  local nonce = now()
  for id,_ in pairs(set) do
    local key = db.controllerKeys[tag] and db.controllerKeys[tag][tostring(id)]
    local mac = key and config_util.hash(key..tag..tostring(duration)..tostring(nonce), "") or nil
    rednet.send(id, {type="open", tag=tag, duration=duration, nonce=nonce, mac=mac}, OPEN_EVENT)
  end
end
--------------------------------------------

------------- Door Helpers -----------------
local function ensureDoor(tag)
  db.doors[tag] = db.doors[tag] or { pins={}, openTime=3 }
  return db.doors[tag]
end

local function hasDoorCode(tag, code)
  local d = db.doors[tag]
  if not d then return false end
  code = tostring(code)
  for _,rec in ipairs(d.pins) do
    if config_util.checkSecret(code, rec) then return true end
  end
  return false
end

local function addPin(tag, pin)
  ensureDoor(tag)
  pin = tostring(pin)
  if hasDoorCode(tag, pin) then return false end
  table.insert(db.doors[tag].pins, config_util.hashSecret(pin))
  return true
end

local function removePin(tag,pin)
  local d=db.doors[tag]
  if not d then return false end
  pin=tostring(pin)
  local out,removed={},false
  for _,rec in ipairs(d.pins) do
    if (not removed) and config_util.checkSecret(pin, rec) then
      removed = true
    else
      table.insert(out, rec)
    end
  end
  d.pins=out
  return removed
end

local function doorSummary()
  local out = {}
  for tag,d in pairs(db.doors) do
    out[tag] = { pinCount = #d.pins, openTime = d.openTime }
  end
  return out
end
--------------------------------------------

------------- User Helpers -----------------
local function ensureUser(name)
  name = trim(name)
  if name == "" then return nil end
  db.users[name] = db.users[name] or {
    codeHash      = nil,
    doors         = {},
    cardTokenHash = nil,
    enabled       = true,
    createdAt     = now(),
  }
  return db.users[name]
end

local function setUserCode(name, code)
  local u = ensureUser(name)
  if not u or trim(code)=="" then return false end
  u.codeHash = config_util.hashSecret(code)
  return true
end

local function clearUserCode(name)
  local u = db.users[trim(name)]
  if not u then return false end
  u.codeHash = nil
  return true
end

local function clearUserDoors(name)
  local u = db.users[trim(name)]
  if not u then return false end
  u.doors = {}
  return true
end

local function setUserDoorEnabled(name, tag, enabled)
  local u = db.users[trim(name)]
  if not u then return false end
  tag = trim(tag)
  if enabled then u.doors[tag] = true else u.doors[tag] = nil end
  return true
end

local function getUserDoors(name)
  local u = db.users[trim(name)]
  if not u then return {} end
  local out = {}
  for tag,on in pairs(u.doors) do
    if on then table.insert(out, tag) end
  end
  table.sort(out)
  return out
end

local function cloneUserAccess(sourceName, targetName, includeCode)
  local src = db.users[trim(sourceName)]
  if not src then return false end
  local dst = ensureUser(targetName)
  if not dst then return false end
  dst.doors = {}
  for tag,on in pairs(src.doors) do
    if on then dst.doors[tag] = true end
  end
  if includeCode then
    dst.codeHash = src.codeHash
  end
  return true
end

local function searchUsers(query)
  query = trim(query):lower()
  local out = {}
  for name,u in pairs(db.users) do
    local haystack = name:lower()
    for tag,on in pairs(u.doors) do
      if on then haystack = haystack.." "..tag:lower() end
    end
    if u.codeHash then haystack = haystack.." code" end
    if u.cardTokenHash then haystack = haystack.." card" end
    if query=="" or haystack:find(query, 1, true) then
      table.insert(out, name)
    end
  end
  table.sort(out)
  return out
end

local function listUsers()
  local out = {}
  for name,u in pairs(db.users) do
    local doorCount = 0
    for _,on in pairs(u.doors) do if on then doorCount = doorCount + 1 end end
    table.insert(out, {
      name      = name,
      doorCount = doorCount,
      hasCode   = u.codeHash ~= nil,
      hasCard   = u.cardTokenHash ~= nil,
      enabled   = u.enabled ~= false,
    })
  end
  table.sort(out, function(a,b) return a.name < b.name end)
  return out
end

local function issueUserCard(name)
  local u = ensureUser(name)
  if not u then return nil end
  local token = config_util.newToken("card")
  local tokenHash = config_util.hash(token, admin.cardPepper)
  if u.cardTokenHash then cardTokenIndex[u.cardTokenHash] = nil end
  u.cardTokenHash = tokenHash
  cardTokenIndex[tokenHash] = trim(name)
  return token
end

local function clearUserCard(name)
  local u = db.users[trim(name)]
  if not u then return false end
  if u.cardTokenHash then cardTokenIndex[u.cardTokenHash] = nil end
  u.cardTokenHash = nil
  return true
end

local function removeUser(name)
  name = trim(name)
  local u = db.users[name]
  if not u then return false end
  if u.cardTokenHash then cardTokenIndex[u.cardTokenHash] = nil end
  db.users[name] = nil
  return true
end
--------------------------------------------

------------- Access Verification ----------
-- Precedence: lockdown/lockout short-circuit, then card token, then per-user
-- code, then legacy per-door PIN list. `reason` doubles as the attribution
-- string used for audit logging.
local function verifyAccess(tag, code, senderId)
  if lockdown then return false, "lockdown" end

  local perSenderKey = "verify:"..tag..":"..tostring(senderId)
  local perTagKey    = "verify:"..tag
  if isLocked(perSenderKey) or isLocked(perTagKey) then
    return false, "locked_out"
  end

  local candidateHash = config_util.hash(code, admin.cardPepper or "")
  local cardUser = cardTokenIndex[candidateHash]
  if cardUser and db.users[cardUser] and db.users[cardUser].enabled ~= false
     and db.users[cardUser].doors[tag] then
    return true, "card:"..cardUser
  end

  for name,u in pairs(db.users) do
    if u.enabled ~= false and u.doors[tag] and u.codeHash
       and config_util.checkSecret(code, u.codeHash) then
      return true, "user:"..name
    end
  end

  if hasDoorCode(tag, code) then
    return true, "doorpin"
  end

  return false, "denied"
end
--------------------------------------------

---------------- Remote Admin --------------
local function handleRemoteAdmin(sender,msg)

  --------------------------------------------------
  -- LOGIN CHALLENGE (discloses only the salt)
  --------------------------------------------------
  if msg.type=="admin_login_challenge" then
    rednet.send(sender, {type="admin_login_challenge_salt", salt=admin.pinRecord.salt}, PROTOCOL)
    return true
  end

  --------------------------------------------------
  -- REMOTE LOGIN
  --------------------------------------------------
  if msg.type=="admin_login" then
    local stamp = tostring(msg.timestamp or "")
    local sig   = tostring(msg.sig or "")
    local senderKey = "adminlogin:"..tostring(sender)

    if isLocked(senderKey) then
      rednet.send(sender,{type="admin_login_locked"},PROTOCOL)
      logEvent({event="admin_login", ok=false, source="remote#"..sender, detail="locked_out"})
      return true
    end

    local stampNum = tonumber(stamp)
    local freshEnough = stampNum and math.abs(now()-stampNum) <= (ADMIN_LOGIN_WINDOW_SEC*1000)
    local alreadySeen = seenStamps[stamp] or false

    if not freshEnough or alreadySeen then
      noteFailure(senderKey, ADMIN_MAX_ATTEMPTS, ADMIN_WINDOW_SEC, ADMIN_LOCK_BASE_SEC, ADMIN_LOCK_MAX_SEC)
      local reason = alreadySeen and "replay" or "stale"
      rednet.send(sender,{type="admin_login_fail", reason=reason},PROTOCOL)
      logEvent({event="admin_login", ok=false, source="remote#"..sender, detail=reason})
      return true
    end

    -- Consume this stamp regardless of outcome below.
    seenStamps[stamp] = true
    table.insert(seenOrder, stamp)
    if #seenOrder > REPLAY_RING_SIZE then
      local oldest = table.remove(seenOrder, 1)
      seenStamps[oldest] = nil
    end

    local expected = config_util.hash(admin.pinRecord.hash .. stamp, "")

    if sig == expected then
      noteSuccess(senderKey)
      local token = config_util.newToken("sess")
      admin.loggedIn   = true
      admin.remoteToken= token
      admin.lastAction = now()

      logEvent({event="admin_login", ok=true, source="remote#"..sender})
      rednet.send(sender,{type="admin_login_ok", token=token},PROTOCOL)
    else
      noteFailure(senderKey, ADMIN_MAX_ATTEMPTS, ADMIN_WINDOW_SEC, ADMIN_LOCK_BASE_SEC, ADMIN_LOCK_MAX_SEC)
      logEvent({event="admin_login", ok=false, source="remote#"..sender, detail="bad_sig"})
      rednet.send(sender,{type="admin_login_fail", reason="bad_sig"},PROTOCOL)
    end

    return true
  end

  --------------------------------------------------
  -- REMOTE COMMANDS
  --------------------------------------------------
  if msg.type=="admin_cmd" then
    if msg.token ~= admin.remoteToken or not isAdminValid() then
      rednet.send(sender,{type="admin_denied"},PROTOCOL)
      return true
    end

    admin.lastAction = now()
    local cmd = msg.cmd

    if cmd=="list" then
      rednet.send(sender,{type="admin_list", doors=doorSummary()},PROTOCOL)

    elseif cmd=="show" then
      local tag = trim(msg.tag or "")
      rednet.send(sender,{type="admin_show", tag=tag, door=doorSummary()[tag]},PROTOCOL)

    elseif cmd=="add" then
      local ok=addPin(msg.tag,msg.pin)
      logEvent({event="pin_add", tag=msg.tag, ok=ok, source="remote"})
      rednet.send(sender,{type="admin_result",ok=ok},PROTOCOL)

    elseif cmd=="del" then
      local ok=removePin(msg.tag,msg.pin)
      logEvent({event="pin_del", tag=msg.tag, ok=ok, source="remote"})
      rednet.send(sender,{type="admin_result",ok=ok},PROTOCOL)

    elseif cmd=="remove" then
      db.doors[msg.tag]=nil
      logEvent({event="door_remove", tag=msg.tag, ok=true, source="remote"})
      rednet.send(sender,{type="admin_result",ok=true},PROTOCOL)

    elseif cmd=="opentime" then
      ensureDoor(msg.tag)
      db.doors[msg.tag].openTime = tonumber(msg.seconds)
      logEvent({
        event="opentime_set", tag=msg.tag,
        ok=true, source="remote",
        detail="seconds="..tostring(msg.seconds)
      })
      rednet.send(sender,{type="admin_result",ok=true},PROTOCOL)

    elseif cmd=="lockdown_on" then
      lockdown=true
      logEvent({event="lockdown_on", ok=true, source="remote"})
      rednet.send(sender,{type="admin_result",ok=true,state="locked"},PROTOCOL)

    elseif cmd=="lockdown_off" then
      lockdown=false
      logEvent({event="lockdown_off", ok=true, source="remote"})
      rednet.send(sender,{type="admin_result",ok=true,state="unlocked"},PROTOCOL)

    elseif cmd=="open" then
      if lockdown then
        logEvent({event="remote_open", tag=msg.tag, ok=false, source="remote", detail="blocked_by_lockdown"})
        rednet.send(sender,{type="admin_result",ok=false,reason="lockdown"},PROTOCOL)
        return true
      end
      local d=db.doors[msg.tag]
      local dur=(d and d.openTime) or 3
      broadcastOpen(msg.tag,dur)
      logEvent({event="remote_open",tag=msg.tag,ok=true,source="remote"})
      rednet.send(sender,{type="admin_result",ok=true},PROTOCOL)

    elseif cmd=="logs" then
      rednet.send(sender,{type="admin_logs", logs=logs},PROTOCOL)

    elseif cmd=="user_list" then
      rednet.send(sender,{type="admin_users", users=listUsers()},PROTOCOL)

    elseif cmd=="user_search" then
      rednet.send(sender,{type="admin_users_names", names=searchUsers(msg.query or "")},PROTOCOL)

    elseif cmd=="user_show" then
      local name = trim(msg.name or "")
      local u = db.users[name]
      if u then
        rednet.send(sender,{type="admin_user", name=name,
          hasCode=u.codeHash~=nil, hasCard=u.cardTokenHash~=nil,
          enabled=u.enabled~=false, doors=getUserDoors(name)},PROTOCOL)
      else
        rednet.send(sender,{type="admin_user", name=name, notFound=true},PROTOCOL)
      end

    elseif cmd=="user_add" then
      local ok=setUserCode(msg.name, msg.code)
      logEvent({event="user_add", tag=msg.name, ok=ok, source="remote"})
      rednet.send(sender,{type="admin_result",ok=ok},PROTOCOL)

    elseif cmd=="user_clear_code" then
      local ok=clearUserCode(msg.name)
      logEvent({event="user_clear_code", tag=msg.name, ok=ok, source="remote"})
      rednet.send(sender,{type="admin_result",ok=ok},PROTOCOL)

    elseif cmd=="user_clear_doors" then
      local ok=clearUserDoors(msg.name)
      logEvent({event="user_clear_doors", tag=msg.name, ok=ok, source="remote"})
      rednet.send(sender,{type="admin_result",ok=ok},PROTOCOL)

    elseif cmd=="user_clone" then
      local ok=cloneUserAccess(msg.source, msg.name, msg.includeCode)
      logEvent({event="user_clone", tag=msg.name, ok=ok, source="remote", detail="from="..tostring(msg.source)})
      rednet.send(sender,{type="admin_result",ok=ok},PROTOCOL)

    elseif cmd=="user_card_issue" then
      local token = issueUserCard(msg.name)
      logEvent({event="user_card_issue", tag=msg.name, ok=token~=nil, source="remote"})
      rednet.send(sender,{type="admin_user_card", ok=token~=nil, token=token, name=msg.name},PROTOCOL)

    elseif cmd=="user_card_clear" then
      local ok=clearUserCard(msg.name)
      logEvent({event="user_card_clear", tag=msg.name, ok=ok, source="remote"})
      rednet.send(sender,{type="admin_result",ok=ok},PROTOCOL)

    elseif cmd=="user_del" then
      local ok=removeUser(msg.name)
      logEvent({event="user_del", tag=msg.name, ok=ok, source="remote"})
      rednet.send(sender,{type="admin_result",ok=ok},PROTOCOL)

    elseif cmd=="user_enable" then
      local ok=setUserDoorEnabled(msg.name, msg.tag, true)
      logEvent({event="user_enable", tag=msg.tag, ok=ok, source="remote", detail="user="..tostring(msg.name)})
      rednet.send(sender,{type="admin_result",ok=ok},PROTOCOL)

    elseif cmd=="user_disable" then
      local ok=setUserDoorEnabled(msg.name, msg.tag, false)
      logEvent({event="user_disable", tag=msg.tag, ok=ok, source="remote", detail="user="..tostring(msg.name)})
      rednet.send(sender,{type="admin_result",ok=ok},PROTOCOL)

    elseif cmd=="user_doors" then
      rednet.send(sender,{type="admin_user_doors", name=msg.name, doors=getUserDoors(msg.name)},PROTOCOL)
    end

    return true
  end

  return false
end
--------------------------------------------

---------------- Handlers ------------------
local function handleMessage(sender,msg,proto)
  if proto~=PROTOCOL or type(msg)~="table" then return end

  -- remote admin first
  if handleRemoteAdmin(sender,msg) then return end

  -------- door_list (for door_fob) --------
  if msg.type=="door_list" then
    local tags={}
    for tag,_ in pairs(db.doors) do table.insert(tags,tag) end
    rednet.send(sender,{type="door_list",tags=tags},PROTOCOL)
    return
  end

  -------------- status (keypads + lockdown_alarm) --------
  if msg.type=="status" then
    local tag = msg.tag and trim(msg.tag) or nil
    rednet.send(sender,{
      type="status_result",
      tag=tag,
      lockdown=lockdown,
      door=(tag and db.doors[tag]) or nil,
      server=HOST_NAME,
    },PROTOCOL)
    return
  end

  -------------- verify (keypads + fob) -----
  if msg.type=="verify" then
    local tag=trim(msg.tag)
    local code=trim(msg.code or msg.pin)

    local ok, reason = verifyAccess(tag, code, sender)

    if reason=="lockdown" or reason=="locked_out" then
      rednet.send(sender,{type="verify_result",ok=false,tag=tag,reason=reason},PROTOCOL)
      logEvent({event="pin_attempt",tag=tag,ok=false,source="keypad#"..sender,detail=reason})
      return
    end

    if ok then
      noteSuccess("verify:"..tag..":"..tostring(sender))
    else
      noteFailure("verify:"..tag..":"..tostring(sender), VERIFY_MAX_ATTEMPTS, VERIFY_WINDOW_SEC, VERIFY_LOCK_BASE_SEC, VERIFY_LOCK_MAX_SEC)
      noteFailure("verify:"..tag, VERIFY_MAX_ATTEMPTS*3, VERIFY_WINDOW_SEC, VERIFY_LOCK_BASE_SEC, VERIFY_LOCK_MAX_SEC)
    end

    rednet.send(sender,{type="verify_result",ok=ok,tag=tag,reason=reason},PROTOCOL)

    local userName = reason and reason:match("^user:(.+)$")
    local cardName = reason and reason:match("^card:(.+)$")
    local sourceLabel = userName and ("user#"..userName)
                      or (cardName and ("card#"..cardName))
                      or ("keypad#"..sender)

    logEvent({
      event="pin_attempt",
      tag=tag, ok=ok,
      source=sourceLabel,
      detail=(not ok) and reason or nil,
    })

    if ok then
      local d=db.doors[tag]
      local dur=(d and d.openTime) or 3
      broadcastOpen(tag,dur)
      logEvent({event="door_open",tag=tag,ok=true,source=sourceLabel})
    end

    return
  end

  -------------- controller registration ----
  if msg.type=="registerController" then
    local tag=trim(msg.tag)

    if msg.regSecret ~= REGISTRATION_SECRET then
      rednet.send(sender,{type="register_denied", reason="bad_secret"},PROTOCOL)
      logEvent({event="controller_register_denied",tag=tag,ok=false,source="ctrl#"..sender})
      return
    end

    ensureDoor(tag)
    controllersByTag[tag]=controllersByTag[tag] or {}
    controllersByTag[tag][sender]=true

    db.controllerKeys[tag] = db.controllerKeys[tag] or {}
    local key = db.controllerKeys[tag][tostring(sender)]
    if not key then
      key = config_util.newToken("ctrlkey")
      db.controllerKeys[tag][tostring(sender)] = key
    end

    rednet.send(sender,{type="register_ack",tag=tag,controllerKey=key},PROTOCOL)
    logEvent({event="controller_register",tag=tag,ok=true,source="ctrl#"..sender})
    return
  end

  if msg.type=="unregisterController" then
    local tag=trim(msg.tag)
    if controllersByTag[tag] then controllersByTag[tag][sender]=nil end
    rednet.send(sender,{type="unregister_ack"},PROTOCOL)
    logEvent({event="controller_unregister",tag=tag,ok=true,source="ctrl#"..sender})
    return
  end
end
--------------------------------------------

---------------- Console -------------------
local function help()
  print([[Commands:
  help
  controllers
  save
  reboot
  cls

  -- Door commands (admin) --
  add <tag> <pin>
  del <tag> <pin>
  opentime <tag> <seconds>
  remove <tag>
  show <tag>
  list
  lockdown_on
  lockdown_off
  logs

  -- User commands (admin) --
  users
  user_show <name>
  user_add <name> <code>
  user_del <name>
  user_clear_code <name>
  user_clear_doors <name>
  user_enable <name> <tag>
  user_disable <name> <tag>
  user_doors <name>
  user_card_issue <name>
  user_card_clear <name>
  user_clone <source> <target> [yes|no]
  user_search <query>
]])
end

local function printLogsConsole(maxLines)
  if not requireAdmin() then return end
  maxLines=maxLines or 40
  local n=#logs
  local start = math.max(1, n-maxLines+1)
  for i=start,n do
    local e=logs[i]
    local status = e.ok==nil and "" or (e.ok and "OK" or "FAIL")
    print(("[%4d] %s %-14s tag=%s %s %s")
      :format(
        i,
        e.time or "??:??",
        e.event or "?",
        e.tag or "-",
        status,
        e.detail or ""
      ))
  end
end

local function consoleLoop()
  help()
  while true do
    term.setTextColor(colors.yellow) write("> ")
    term.setTextColor(colors.white)
    local line=read()

    local args={}
    for w in line:gmatch("%S+") do table.insert(args,w) end
    local cmd=args[1]

    if cmd=="help" then help()
    elseif cmd=="cls" or cmd=="clear" then term.clear() term.setCursorPos(1,1)

    elseif cmd=="controllers" then
      for tag,set in pairs(controllersByTag) do
        local ids={}
        for id,_ in pairs(set) do table.insert(ids,id) end
        print(tag.." -> "..table.concat(ids,",")) end

    elseif cmd=="save" then saveDB() saveLogs()
    elseif cmd=="reboot" then saveDB() saveLogs() sleep(0.2) os.reboot()

    elseif cmd=="list" then
      if requireAdmin() then
        for tag,d in pairs(db.doors) do
          print(("- %s (pins:%d, open:%ds)")
            :format(tag,#d.pins,d.openTime or 3))
        end
      end

    elseif cmd=="show" and args[2] then
      if requireAdmin() then
        local d=db.doors[args[2]]
        if not d then print("No such door.") else
          print("OpenTime:",d.openTime)
          print("Pins: "..#d.pins.." (hashed)")
        end
      end

    elseif cmd=="add" and args[2] and args[3] then
      if requireAdmin() then
        local ok=addPin(args[2],args[3])
        logEvent({event="pin_add",tag=args[2],ok=ok,source="console"})
        print(ok and "Added." or "Already present.")
      end

    elseif cmd=="del" and args[2] and args[3] then
      if requireAdmin() then
        local ok=removePin(args[2],args[3])
        logEvent({event="pin_del",tag=args[2],ok=ok,source="console"})
        print(ok and "Removed." or "Not found.")
      end

    elseif cmd=="opentime" and args[2] and tonumber(args[3]) then
      if requireAdmin() then
        ensureDoor(args[2])
        db.doors[args[2]].openTime = tonumber(args[3])
        logEvent({event="opentime_set",tag=args[2],ok=true,source="console"})
        print("Updated.")
      end

    elseif cmd=="remove" and args[2] then
      if requireAdmin() then
        db.doors[args[2]]=nil
        logEvent({event="door_remove",tag=args[2],ok=true,source="console"})
        print("Door removed.")
      end

    elseif cmd=="lockdown_on" then
      if requireAdmin() then
        lockdown=true
        logEvent({event="lockdown_on",ok=true,source="console"})
        print("LOCKDOWN ENABLED")
      end

    elseif cmd=="lockdown_off" then
      if requireAdmin() then
        lockdown=false
        logEvent({event="lockdown_off",ok=true,source="console"})
        print("Lockdown disabled.")
      end

    elseif cmd=="logs" then
      printLogsConsole(40)

    elseif cmd=="users" then
      if requireAdmin() then
        for _,u in ipairs(listUsers()) do
          print(("- %s (doors:%d, code:%s, card:%s)")
            :format(u.name, u.doorCount, u.hasCode and "yes" or "no", u.hasCard and "yes" or "no"))
        end
      end

    elseif cmd=="user_show" and args[2] then
      if requireAdmin() then
        local u = db.users[args[2]]
        if not u then print("No such user.") else
          print("Code set:", u.codeHash~=nil)
          print("Card set:", u.cardTokenHash~=nil)
          print("Doors:", table.concat(getUserDoors(args[2]), ", "))
        end
      end

    elseif cmd=="user_add" and args[2] and args[3] then
      if requireAdmin() then
        local ok=setUserCode(args[2],args[3])
        logEvent({event="user_add",tag=args[2],ok=ok,source="console"})
        print(ok and "User code set." or "Failed.")
      end

    elseif cmd=="user_del" and args[2] then
      if requireAdmin() then
        local ok=removeUser(args[2])
        logEvent({event="user_del",tag=args[2],ok=ok,source="console"})
        print(ok and "User removed." or "No such user.")
      end

    elseif cmd=="user_clear_code" and args[2] then
      if requireAdmin() then
        local ok=clearUserCode(args[2])
        logEvent({event="user_clear_code",tag=args[2],ok=ok,source="console"})
        print(ok and "Code cleared." or "No such user.")
      end

    elseif cmd=="user_clear_doors" and args[2] then
      if requireAdmin() then
        local ok=clearUserDoors(args[2])
        logEvent({event="user_clear_doors",tag=args[2],ok=ok,source="console"})
        print(ok and "Doors cleared." or "No such user.")
      end

    elseif cmd=="user_enable" and args[2] and args[3] then
      if requireAdmin() then
        local ok=setUserDoorEnabled(args[2],args[3],true)
        logEvent({event="user_enable",tag=args[3],ok=ok,source="console",detail="user="..args[2]})
        print(ok and "Enabled." or "No such user.")
      end

    elseif cmd=="user_disable" and args[2] and args[3] then
      if requireAdmin() then
        local ok=setUserDoorEnabled(args[2],args[3],false)
        logEvent({event="user_disable",tag=args[3],ok=ok,source="console",detail="user="..args[2]})
        print(ok and "Disabled." or "No such user.")
      end

    elseif cmd=="user_doors" and args[2] then
      if requireAdmin() then
        print(table.concat(getUserDoors(args[2]), ", "))
      end

    elseif cmd=="user_card_issue" and args[2] then
      if requireAdmin() then
        local token = issueUserCard(args[2])
        logEvent({event="user_card_issue",tag=args[2],ok=token~=nil,source="console"})
        print(token and ("Card token: "..token) or "Failed.")
      end

    elseif cmd=="user_card_clear" and args[2] then
      if requireAdmin() then
        local ok=clearUserCard(args[2])
        logEvent({event="user_card_clear",tag=args[2],ok=ok,source="console"})
        print(ok and "Card cleared." or "No such user.")
      end

    elseif cmd=="user_clone" and args[2] and args[3] then
      if requireAdmin() then
        local includeCode = args[4]=="yes"
        local ok=cloneUserAccess(args[2],args[3],includeCode)
        logEvent({event="user_clone",tag=args[3],ok=ok,source="console",detail="from="..args[2]})
        print(ok and "Cloned." or "Failed.")
      end

    elseif cmd=="user_search" then
      if requireAdmin() then
        local query = table.concat(args, " ", 2)
        for _,name in ipairs(searchUsers(query or "")) do print("- "..name) end
      end

    elseif cmd and cmd~="" then
      print("Unknown command.")
    end
  end
end
--------------------------------------------

---------------- Network -------------------
local function netLoop()
  while true do
    local id,msg,proto = rednet.receive()
    handleMessage(id,msg,proto)
  end
end

local function autosaveLoop()
  while true do
    sleep(SAVE_INTERVAL)
    saveDB()
    saveLogs()
  end
end

local function heartbeatLoop()
  while true do
    sleep(HEARTBEAT_RATE)
    for tag,set in pairs(controllersByTag) do
      for id,_ in pairs(set) do
        rednet.send(id,{type="hb"},HEARTBEAT_EVENT)
      end
    end
  end
end
--------------------------------------------

------------------- Main -------------------
term.setTextColor(colors.cyan)
print("[DoorAuth Server] starting...")
term.setTextColor(colors.white)

config_util.randomSeedOnce()
openModems()
rednet.host(PROTOCOL, HOST_NAME)
loadDB()
loadLogs()
loadAdmin()
logEvent({event="server_start",ok=true,source="server"})

parallel.waitForAny(netLoop, consoleLoop, autosaveLoop, heartbeatLoop)
