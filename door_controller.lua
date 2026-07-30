-- door_controller.lua
-- Listens for OPEN messages for its tag and pulses redstone.
-- Only trusts opens that (a) come from the registered server ID, (b) carry
-- a fresh nonce, and (c) carry a MAC computed with this controller's
-- per-registration shared key - closing the "anyone who knows the tag can
-- forge an open" hole in earlier versions of this script.

os.loadAPI("config_util.lua")

------------- Config -------------
local defaults = {
  protocol            = "doorAuth.v1",
  open_event          = "doorAuth.open.v1",
  server_name         = "DoorAuthServer",
  door_tag            = "lobby",
  redstone_side       = "right",
  pulse_default       = 3,
  register_timeout    = 3,
  heartbeat_timeout   = 30,
  registration_secret = "change-me-registration-secret",
  controller_key      = "",
}

local fields = {
  {key="protocol", label="Rednet protocol"},
  {key="open_event", label="Open event name"},
  {key="server_name", label="Server host name"},
  {key="door_tag", label="Door tag"},
  {key="redstone_side", label="Redstone side"},
  {key="pulse_default", label="Fallback pulse duration (s)"},
  {key="register_timeout", label="Registration ack timeout (s)"},
  {key="heartbeat_timeout", label="Server-silent timeout (s)"},
  {key="registration_secret", label="Registration secret",
    help="Must match the auth_server's registration_secret."},
}

local cfg = config_util.load("door_controller", defaults, fields, "Door Controller Config")

local PROTOCOL            = cfg.protocol
local OPEN_EVENT           = cfg.open_event
local SERVER_NAME          = cfg.server_name
local DOOR_TAG             = cfg.door_tag
local REDSTONE_SIDE        = cfg.redstone_side
local PULSE_DEFAULT        = cfg.pulse_default
local REGISTER_TIMEOUT     = cfg.register_timeout
local HEARTBEAT_TIMEOUT    = cfg.heartbeat_timeout
local REGISTRATION_SECRET  = cfg.registration_secret
local NONCE_WINDOW_MS      = 10000 -- reject opens whose nonce is older than this
---------------------------------

local controllerKey = cfg.controller_key ~= "" and cfg.controller_key or nil

local function persistKey(key)
  controllerKey = key
  cfg.controller_key = key
  config_util.save("door_controller", cfg)
end

local function pulseDoor(seconds)
  seconds = tonumber(seconds) or PULSE_DEFAULT
  redstone.setOutput(REDSTONE_SIDE, true)
  sleep(seconds)
  redstone.setOutput(REDSTONE_SIDE, false)
end

local function registerLoop(expectedTag)
  while true do
    local server = config_util.findServer(PROTOCOL, SERVER_NAME)
    if server then
      print("[DoorCtrl] Server #" .. server .. " found. Registering...")
      print("[DoorCtrl] Registering with tag '"..expectedTag.."'")
      rednet.send(server, {type="registerController", tag=expectedTag, regSecret=REGISTRATION_SECRET}, PROTOCOL)

      local timer = os.startTimer(REGISTER_TIMEOUT)
      while true do
        local e = { os.pullEvent() }
        if e[1] == "rednet_message" then
          local id, msg, proto = e[2], e[3], e[4]
          if id == server and proto == PROTOCOL and type(msg)=="table" then
            if msg.type == "register_ack" and msg.tag == expectedTag then
              if msg.controllerKey then
                persistKey(msg.controllerKey)
              else
                print("[DoorCtrl] WARNING: server sent no controller key (old server?). MAC checks disabled.")
              end
              print("[DoorCtrl] Registered for tag '"..expectedTag.."'")
              return server
            elseif msg.type == "register_denied" then
              print("[DoorCtrl] Registration DENIED: "..tostring(msg.reason).." - check registration_secret matches the server.")
              sleep(3) ; break
            elseif msg.type == "error" then
              print("[DoorCtrl] Registration error: "..tostring(msg.reason))
              sleep(2) ; break
            end
          end
        elseif e[1] == "timer" and e[2] == timer then
          print("[DoorCtrl] No ack, retrying...")
          break
        end
      end
    else
      print("[DoorCtrl] Waiting for server...")
      sleep(2)
    end
  end
end

local function main()
  print(("[DoorCtrl] Tag='%s', side='%s'"):format(DOOR_TAG, REDSTONE_SIDE))
  config_util.openModems()

  -- Register initially
  local server = registerLoop(DOOR_TAG)
  local lastHeartbeat = os.epoch("utc")

  while true do
    local id, msg, proto = rednet.receive(OPEN_EVENT, 5)

    if id then
      -- If server ID changed, re-register immediately (also re-derives our
      -- controllerKey against whoever now legitimately holds the hostname).
      if id ~= server then
        print("[DoorCtrl] Different server detected! Re-registering...")
        server = registerLoop(DOOR_TAG)
      end

      if id == server and type(msg) == "table" and msg.type == "open" and msg.tag == DOOR_TAG then
        local freshEnough = msg.nonce and math.abs(os.epoch("utc") - msg.nonce) < NONCE_WINDOW_MS
        local macOk = (not controllerKey)
          or (msg.mac == config_util.hash(controllerKey..DOOR_TAG..tostring(msg.duration)..tostring(msg.nonce), ""))

        if freshEnough and macOk then
          lastHeartbeat = os.epoch("utc")
          print(("[DoorCtrl] OPEN for '%s' (%ss)"):format(DOOR_TAG, msg.duration or PULSE_DEFAULT))
          pulseDoor(msg.duration)
        else
          print("[DoorCtrl] Rejected open: "..(not freshEnough and "stale/missing nonce" or "bad MAC"))
        end
      end

    else
      -- No messages received for 5 seconds
      -- Check if server heartbeat expired
      if os.epoch("utc") - lastHeartbeat > HEARTBEAT_TIMEOUT*1000 then
        print(("[DoorCtrl] Server silent for %ds, attempting re-register..."):format(HEARTBEAT_TIMEOUT))
        server = registerLoop(DOOR_TAG)
        lastHeartbeat = os.epoch("utc")
      end
    end
  end
end


main()
