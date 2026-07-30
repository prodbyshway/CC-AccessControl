--============================================================--
--  config_util.lua
--  Shared helper API for all DoorAuth programs. Load with:
--      os.loadAPI("config_util.lua")
--  which exposes everything below as the global table `config_util`.
--
--  Provides:
--    - JSON config persistence with an interactive startup prompt
--    - Salted secret hashing (NOT cryptographic - see hash() below)
--    - Token generation
--    - Small net/file helpers shared by every DoorAuth script
--============================================================--

local CONFIG_PATH = "doorauth_config.json"
local SEEDED = false

----------------------------------------------------------------
-- File / JSON helpers
----------------------------------------------------------------
function readAll(path)
  if not fs.exists(path) then return nil end
  local h = fs.open(path, "r")
  local data = h.readAll()
  h.close()
  return data
end

function writeAll(path, data)
  local h = fs.open(path, "w")
  h.write(data)
  h.close()
end

function jsonEncode(tbl)
  if textutils.serializeJSON then return textutils.serializeJSON(tbl) end
  return textutils.serialize(tbl)
end

function jsonDecode(s)
  if not s then return nil end
  if textutils.unserializeJSON then return textutils.unserializeJSON(s) end
  return textutils.unserialize(s)
end

function trim(s)
  s = tostring(s or "")
  return s:gsub("^%s+", ""):gsub("%s+$", "")
end

----------------------------------------------------------------
-- Networking helpers
----------------------------------------------------------------
function openModems()
  for _, side in ipairs(rs.getSides()) do
    if peripheral.getType(side) == "modem" then
      if not rednet.isOpen(side) then rednet.open(side) end
    end
  end
end

function findServer(protocol, name)
  return rednet.lookup(protocol, name)
end

----------------------------------------------------------------
-- Config: deep copy / defaults merge
----------------------------------------------------------------
local function deepCopy(value)
  if type(value) ~= "table" then return value end
  local out = {}
  for k, v in pairs(value) do out[deepCopy(k)] = deepCopy(v) end
  return out
end

local function mergeDefaults(defaults, cfg)
  local out = deepCopy(defaults or {})
  cfg = cfg or {}
  for k, v in pairs(cfg) do
    if type(v) == "table" and type(out[k]) == "table" then
      out[k] = mergeDefaults(out[k], v)
    else
      out[k] = v
    end
  end
  return out
end

local function loadRoot()
  local parsed = jsonDecode(readAll(CONFIG_PATH))
  return type(parsed) == "table" and parsed or {}
end

local function saveRoot(root)
  writeAll(CONFIG_PATH, jsonEncode(root))
end

local function normalizeValue(raw, current)
  if type(current) == "number" then
    local v = tonumber(raw)
    return v ~= nil and v or current
  end
  if type(current) == "boolean" then
    local v = tostring(raw or ""):lower()
    if v == "true" or v == "yes" or v == "1" or v == "y" then return true end
    if v == "false" or v == "no" or v == "0" or v == "n" then return false end
    return current
  end
  return tostring(raw or current or "")
end

local function fieldValue(cfg, field)
  local v = cfg[field.key]
  if v == nil then return "" end
  if type(v) == "boolean" then return v and "true" or "false" end
  return tostring(v)
end

----------------------------------------------------------------
-- Interactive config loader
--   section  = string key this script owns in doorauth_config.json
--   defaults = table of default values
--   fields   = array of {key=, label=, help=} describing editable fields
--   title    = heading printed on the setup screen
----------------------------------------------------------------
function load(section, defaults, fields, title)
  local root = loadRoot()
  local cfg = mergeDefaults(defaults, root[section])
  root[section] = cfg
  saveRoot(root)

  term.clear()
  term.setCursorPos(1, 1)
  print(title or ("=== " .. section .. " Config ==="))
  print("Press any key within 3 seconds to edit settings...")

  local openMenu = false
  local timer = os.startTimer(3)
  while true do
    local ev = { os.pullEvent() }
    if ev[1] == "timer" and ev[2] == timer then
      break
    elseif ev[1] == "key" or ev[1] == "char" or ev[1] == "mouse_click" then
      openMenu = true
      break
    end
  end

  if openMenu then
    while true do
      term.clear()
      term.setCursorPos(1, 1)
      print(title or section)
      print("")
      for i, field in ipairs(fields) do
        print(("%d) %-22s = %s"):format(i, field.label or field.key, fieldValue(cfg, field)))
      end
      print("")
      print("S) Save and continue    Q) Continue without saving edits")
      write("> ")
      local choice = trim(read())
      local idx = tonumber(choice)
      if idx and fields[idx] then
        local field = fields[idx]
        if field.help then print(field.help) end
        write("New value: ")
        local raw = read()
        cfg[field.key] = normalizeValue(raw, cfg[field.key])
      elseif choice:lower() == "s" then
        root[section] = cfg
        saveRoot(root)
        print("Saved configuration.")
        sleep(0.5)
        break
      elseif choice:lower() == "q" or choice == "" then
        break
      end
    end
  end

  root[section] = cfg
  saveRoot(root)
  return cfg
end

-- Persist an updated config table for `section` outside the interactive flow
-- (e.g. a script storing a value it generated at runtime, like a controller key).
function save(section, cfg)
  local root = loadRoot()
  root[section] = cfg
  saveRoot(root)
end

----------------------------------------------------------------
-- Hashing / salting / tokens
--
-- NOTE: this is NOT a cryptographic hash. CC:Tweaked's Lua 5.1 sandbox has
-- no confirmed bitwise-operator support and no OS-level CSPRNG, so this is a
-- salted, multi-lane mixing hash with a fixed substitution box - meaningfully
-- stronger than a bare `h*31+byte` rolling hash, but not a substitute for a
-- real KDF outside this game's threat model.
----------------------------------------------------------------
local STATE_MOD = 2147483648 -- 2^31
local OUT_MOD   = 16777216   -- 2^24, keeps lanes safely inside %06x

local SBOX = {}
do
  local seed = 104729
  for i = 0, 255 do
    seed = (seed * 1103515245 + 12345) % STATE_MOD
    SBOX[i + 1] = seed % 256
  end
end

local function laneHash(salt, data, seed, mult)
  local state = seed % STATE_MOD
  local combined = tostring(salt) .. "\0" .. tostring(data)
  for i = 1, #combined do
    local b = combined:byte(i)
    local sub = SBOX[(b % 256) + 1]
    state = (state * mult + sub + 1) % STATE_MOD
    state = (state * 2654435761 + 2654435761) % STATE_MOD
  end
  for _ = 1, 3 do
    state = (state * mult + 12345) % STATE_MOD
  end
  return state % OUT_MOD
end

-- hash(secret, salt) -> 24-hex-char digest. `salt` may be "" for unsalted use
-- (e.g. mixing a login signature over an already-salted stored hash).
function hash(secret, salt)
  salt = tostring(salt or "")
  secret = tostring(secret or "")
  return string.format("%06x%06x%06x%06x",
    laneHash(salt, secret, 5381, 16777619),
    laneHash(salt, secret, 2166136261 % STATE_MOD, 2654435761 % STATE_MOD),
    laneHash(salt, secret, 1013904223 % STATE_MOD, 40503),
    laneHash(salt, secret, 314159265 % STATE_MOD, 2246822519 % STATE_MOD))
end

-- Seed math.random exactly once per running script, before any newSalt/
-- newToken/hashSecret call. Safe to call repeatedly; only the first call
-- does anything.
function randomSeedOnce()
  if SEEDED then return end
  SEEDED = true

  local seed = os.epoch("utc") % 2147483647
  seed = (seed + (os.epoch("local") % 104729)) % 2147483647

  local okClock, clock = pcall(os.clock)
  if okClock and clock then
    seed = (seed + math.floor(clock * 1000)) % 2147483647
  end

  local okId, id = pcall(os.getComputerID)
  if okId and id then
    seed = (seed + id * 7919) % 2147483647
  end

  math.randomseed(seed)
  for _ = 1, 32 do math.random() end -- stir the generator past its initial state
end

function newSalt()
  randomSeedOnce()
  local parts = {}
  for i = 1, 8 do
    parts[i] = string.format("%02x", math.random(0, 255))
  end
  return table.concat(parts)
end

-- newToken(label) -> a long, whitened pseudo-random token. `label` is an
-- optional human-readable prefix - it is NOT part of the secret material.
function newToken(label)
  randomSeedOnce()
  local raw = {}
  for i = 1, 24 do
    raw[i] = string.format("%02x", math.random(0, 255))
  end
  local whitened = hash(table.concat(raw), tostring(os.epoch("utc")) .. tostring(math.random(0, 999999999)))
  local prefix = label and (tostring(label) .. "_") or ""
  return prefix .. whitened
end

-- hashSecret(secret) -> {salt=, hash=} suitable for storing at rest.
function hashSecret(secret)
  randomSeedOnce()
  local salt = newSalt()
  return { salt = salt, hash = hash(secret, salt) }
end

-- checkSecret(secret, record) -> boolean. `record` is a {salt=, hash=} table.
function checkSecret(secret, record)
  if type(record) ~= "table" or not record.salt or not record.hash then return false end
  return hash(secret, record.salt) == record.hash
end
