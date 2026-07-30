-- keypad_door.lua
-- Touchscreen/terminal keypad. Accepts a typed PIN/code, or a magnetic-card
-- swipe if a card-reader peripheral is attached, and sends either as the
-- same {type="verify", tag, code} message - the server decides what the
-- credential actually resolves to (door PIN, user code, or card token).

os.loadAPI("config_util.lua")

------------- Config -------------
local defaults = {
  protocol              = "doorAuth.v1",
  server_name           = "DoorAuthServer",
  door_tag              = "lobby",
  request_timeout       = 3,
  max_code_length       = 12,
  entry_label           = "Code",
  status_poll_interval  = 5,
}

local fields = {
  {key="protocol", label="Rednet protocol"},
  {key="server_name", label="Server host name"},
  {key="door_tag", label="Door tag"},
  {key="request_timeout", label="Server request timeout (s)"},
  {key="max_code_length", label="Max typed code length"},
  {key="entry_label", label="On-screen entry label"},
  {key="status_poll_interval", label="Lockdown status poll interval (s)"},
}

local cfg = config_util.load("keypad_door", defaults, fields, "Keypad Config")

local PROTOCOL             = cfg.protocol
local SERVER_NAME           = cfg.server_name
local DOOR_TAG              = cfg.door_tag
local REQUEST_TIMEOUT       = cfg.request_timeout
local MAX_CODE_LENGTH       = cfg.max_code_length
local ENTRY_LABEL           = cfg.entry_label
local STATUS_POLL_INTERVAL  = cfg.status_poll_interval
---------------------------------

local trim = config_util.trim

local sharedState = { lockdown = false }

-- ---------- Card reader ----------
local function findCardManipulator()
  for _, name in ipairs(peripheral.getNames()) do
    local p = peripheral.wrap(name)
    if p and type(p.hasCard) == "function" and type(p.readCard) == "function" then
      return name, p
    end
  end
  return nil
end

local function extractCardCode(value)
  if type(value) == "string" or type(value) == "number" then
    return tostring(value)
  end
  if type(value) == "table" then
    for _, key in ipairs({"code","pin","id","uuid","card","value","data","tag"}) do
      if value[key] ~= nil then return tostring(value[key]) end
    end
  end
  return nil
end

local function readCardOnce(reader)
  if not reader.hasCard() then return nil end
  local ok, raw = pcall(reader.readCard)
  if not ok then return nil end
  local code = extractCardCode(raw)
  if not code or trim(code) == "" then return nil, "empty_card" end
  return trim(code)
end

-- ---------- Terminal UI ----------
local function terminalCredential()
  term.clear()
  term.setCursorPos(1,1)
  write("Enter "..ENTRY_LABEL..": ")
  local code = read("*") -- masked
  return code
end

-- ---------- Autoscale + Layout ----------
local function tryScales(mon, scales)
  for _, s in ipairs(scales) do
    mon.setTextScale(s)
    local w,h = mon.getSize()
    if w >= 10 and h >= 9 then return s,w,h end
  end
  return nil, mon.getSize()
end

local function decideLayout(w,h)
  return { compact = (w < 24 or h < 12) }
end

-- ---------- Drawing ----------
local function drawKeypad(mon, layout)
  mon.setBackgroundColor(colors.black)
  mon.setTextColor(colors.white)
  mon.clear()

  local pinY = layout.compact and 1 or 2
  mon.setCursorPos(2, pinY); mon.write(ENTRY_LABEL..":")

  if sharedState.lockdown then
    mon.setCursorPos(2, pinY+1)
    mon.setTextColor(colors.red)
    mon.write("** LOCKDOWN ACTIVE **")
    mon.setTextColor(colors.white)
  end

  local keys = {
    {"1","2","3"},
    {"4","5","6"},
    {"7","8","9"},
    {"CLR","0","OK"},
  }

  local startX, startY, bw, bh, gap
  if layout.compact then
    bw, bh, gap = 3, 1, 1
    startX = 2
    startY = pinY + 2
  else
    bw, bh, gap = 6, 3, 1
    startX = 3
    startY = pinY + 3
  end

  for r=1,4 do
    for c=1,3 do
      local x = startX + (c-1)*(bw+gap)
      local y = startY + (r-1)*(bh+gap)
      for yy=y, y+bh-1 do
        mon.setCursorPos(x, yy)
        mon.write(string.rep(" ", bw))
      end
      local label = keys[r][c]
      mon.setCursorPos(x + math.floor((bw-#label)/2), y + math.floor(bh/2))
      mon.write(label)
    end
  end

  return { keys=keys, startX=startX, startY=startY, bw=bw, bh=bh, gap=gap, pinY=pinY }
end

-- ---------- Keypad Loop ----------
local function keypadLoop(mon)
  tryScales(mon, {0.5, 0.75, 1})
  local w,h = mon.getSize()
  local layout = decideLayout(w,h)
  local geo = drawKeypad(mon, layout)

  local pin = ""
  local function refreshPIN()
    local x = 2 + #ENTRY_LABEL + 2
    mon.setCursorPos(x, geo.pinY)
    mon.write(string.rep(" ", (layout.compact and 10 or 20)))
    mon.setCursorPos(x, geo.pinY)
    mon.write(string.rep("*", #pin))
  end
  refreshPIN()

  local statusTimer = os.startTimer(STATUS_POLL_INTERVAL)

  while true do
    local event, p1, p2, p3 = os.pullEvent()

    if event == "monitor_touch" then
      local touchedSide, x, y = p1, p2, p3
      if peripheral.getName(mon) == touchedSide then
        for r=1,4 do
          for c=1,3 do
            local bx = geo.startX + (c-1)*(geo.bw+geo.gap)
            local by = geo.startY + (r-1)*(geo.bh+geo.gap)
            if x >= bx and x < bx+geo.bw and y >= by and y < by+geo.bh then
              local label = geo.keys[r][c]
              if label == "OK" then return pin
              elseif label == "CLR" then pin = ""; refreshPIN()
              else
                if #pin < MAX_CODE_LENGTH then pin = pin .. label; refreshPIN() end
              end
            end
          end
        end
      end

    elseif event == "char" then
      local ch = p1
      if ch:match("%d") and #pin < MAX_CODE_LENGTH then pin = pin .. ch; refreshPIN() end

    elseif event == "key" then
      local keyCode = p1
      if keyCode == keys.backspace then pin = pin:sub(1, #pin-1); refreshPIN()
      elseif keyCode == keys.enter then return pin end

    elseif event == "timer" and p1 == statusTimer then
      geo = drawKeypad(mon, layout)
      refreshPIN()
      statusTimer = os.startTimer(STATUS_POLL_INTERVAL)
    end
  end
end

-- ---------- Verify ----------
local function requestStatus(server)
  rednet.send(server, {type="status", tag=DOOR_TAG}, PROTOCOL)
  local id, msg = rednet.receive(PROTOCOL, REQUEST_TIMEOUT)
  if id == server and type(msg)=="table" and msg.type=="status_result" then
    sharedState.lockdown = msg.lockdown or false
  end
end

local function verifyWithServer(serverID, tag, code)
  rednet.send(serverID, {type="verify", tag=tag, code=code}, PROTOCOL)
  local timer = os.startTimer(REQUEST_TIMEOUT)
  while true do
    local ev = { os.pullEvent() }
    if ev[1] == "rednet_message" then
      local id, msg, proto = ev[2], ev[3], ev[4]
      if id==serverID and proto==PROTOCOL and type(msg)=="table"
         and msg.type=="verify_result" and msg.tag==tag then
        return msg.ok, msg.reason
      end
    elseif ev[1] == "timer" and ev[2] == timer then
      return false,"timeout"
    end
  end
end

-- ---------- Main ----------
local function main()
  config_util.openModems()
  local mon = peripheral.find("monitor")
  local readerName, reader = findCardManipulator()

  local server = config_util.findServer(PROTOCOL, SERVER_NAME)
  if not server then
    print("Finding server...")
    while not server do sleep(2); server = config_util.findServer(PROTOCOL, SERVER_NAME) end
  end
  print("[Keypad] Server #" .. server .. " | Door '"..DOOR_TAG.."'")
  if readerName then print("[Keypad] Card reader found: "..readerName) end

  requestStatus(server)

  while true do
    local code
    if reader and reader.hasCard() then
      local cardCode, err = readCardOnce(reader)
      code = cardCode
      if not cardCode and mon then drawKeypad(mon, decideLayout(mon.getSize())) end
    else
      code = mon and keypadLoop(mon) or terminalCredential()
    end

    code = trim(code)

    if code == "" then
      if mon then drawKeypad(mon, decideLayout(mon.getSize())) else print("No code entered.") end
    else
      local ok, reason = verifyWithServer(server, DOOR_TAG, code)
      if reason == "lockdown" or reason == "locked_out" then sharedState.lockdown = true end
      local msgText = ok and "GRANTED" or ("DENIED"..(reason and (" ("..reason..")") or ""))
      if mon then
        mon.setCursorPos(2, 1)
        mon.write("Access: "..msgText.."        ")
        sleep(ok and 0.8 or 1.2)
        drawKeypad(mon, decideLayout(mon.getSize()))
      else
        print(ok and "Access GRANTED" or ("Access DENIED"..(reason and (" ("..reason..")") or "")))
      end
    end
  end
end

main()
