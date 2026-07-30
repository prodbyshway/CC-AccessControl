-- lockdown_alarm.lua
-- Polls the auth server for lockdown state and drives a redstone output to
-- match. Deliberately FAILS CLOSED (alarm ON) when the server can't be
-- reached: for a security-signal device, "can't confirm lockdown is off"
-- is treated as a fault condition worth flagging, not a reason to go quiet.

os.loadAPI("config_util.lua")

------------- Config -------------
local defaults = {
  protocol        = "doorAuth.v1",
  server_name     = "DoorAuthServer",
  request_timeout = 3,
  poll_interval   = 2,
  output_side     = "back",
}

local fields = {
  {key="protocol", label="Rednet protocol"},
  {key="server_name", label="Server host name"},
  {key="request_timeout", label="Server request timeout (s)"},
  {key="poll_interval", label="Poll interval (s)"},
  {key="output_side", label="Redstone output side",
    help="A side name (top/bottom/left/right/front/back) or 'all'."},
}

local cfg = config_util.load("lockdown_alarm", defaults, fields, "Lockdown Alarm Config")

local PROTOCOL        = cfg.protocol
local SERVER_NAME       = cfg.server_name
local REQUEST_TIMEOUT   = cfg.request_timeout
local POLL_INTERVAL     = math.max(0.5, tonumber(cfg.poll_interval) or 2)
local OUTPUT_SIDE       = config_util.trim(cfg.output_side or "back"):lower()
---------------------------------

local validSides = {}
for _, side in ipairs(rs.getSides()) do validSides[side] = true end
if OUTPUT_SIDE ~= "all" and not validSides[OUTPUT_SIDE] then
  print("[Alarm] Invalid output_side '"..OUTPUT_SIDE.."', falling back to 'back'.")
  OUTPUT_SIDE = "back"
end

local function setAlarm(active)
  if OUTPUT_SIDE == "all" then
    for _, side in ipairs(rs.getSides()) do
      pcall(redstone.setOutput, side, active)
    end
  else
    pcall(redstone.setOutput, OUTPUT_SIDE, active)
  end
end

local function requestStatus()
  local server = config_util.findServer(PROTOCOL, SERVER_NAME)
  if not server then return nil, "Server offline." end

  rednet.send(server, {type="status"}, PROTOCOL)
  local id, msg = rednet.receive(PROTOCOL, REQUEST_TIMEOUT)
  if id ~= server or type(msg) ~= "table" or msg.type ~= "status_result" then
    return nil, "No response."
  end
  return msg
end

local function drawScreen(stateText, lockdown)
  term.clear()
  term.setCursorPos(1,1)
  print("=== DoorAuth Lockdown Alarm ===")
  print("Server:      "..SERVER_NAME)
  print("Protocol:    "..PROTOCOL)
  print("Output side: "..OUTPUT_SIDE)
  print("Lockdown:    "..tostring(lockdown))
  print("Alarm:       "..stateText)
end

config_util.openModems()

-- Fail closed until we hear otherwise from the server.
setAlarm(true)
drawScreen("SIGNAL ON (no server contact yet)", "unknown")

while true do
  local msg, err = requestStatus()

  if msg and type(msg.lockdown) == "boolean" then
    setAlarm(msg.lockdown)
    drawScreen(msg.lockdown and "SIGNAL ON" or "signal off", msg.lockdown)
  else
    setAlarm(true)
    drawScreen("SIGNAL ON (server offline: "..tostring(err)..")", "unknown")
  end

  sleep(POLL_INTERVAL)
end
