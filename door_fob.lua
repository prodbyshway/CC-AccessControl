-- door_fob.lua
-- Pocket Computer wireless keypad for DoorAuth system
-- Auto-door-discovery + scroll menu, with a choice between typing a PIN/code
-- or entering a magnetic-card token by hand (pocket computers generally
-- don't have a card-manipulator peripheral attached).

os.loadAPI("config_util.lua")

------------- Config -------------
local defaults = {
  protocol         = "doorAuth.v1",
  server_name      = "DoorAuthServer",
  request_timeout  = 3,
}

local fields = {
  {key="protocol", label="Rednet protocol"},
  {key="server_name", label="Server host name"},
  {key="request_timeout", label="Server request timeout (s)"},
}

local cfg = config_util.load("door_fob", defaults, fields, "Door Fob Config")

local PROTOCOL        = cfg.protocol
local SERVER_NAME      = cfg.server_name
local REQUEST_TIMEOUT  = cfg.request_timeout
---------------------------------

local trim = config_util.trim

---------------------------------------------------
-- UTILS
---------------------------------------------------
local function getDoorList()
  local server = config_util.findServer(PROTOCOL, SERVER_NAME)
  if not server then return nil, "Server offline." end

  rednet.send(server, {type="door_list"}, PROTOCOL)
  local id, msg = rednet.receive(PROTOCOL, REQUEST_TIMEOUT)

  if not id then return nil, "Timeout." end
  if msg.type ~= "door_list" then return nil, "Bad response." end

  return msg.tags, nil
end

local function askCredential()
  term.clear()
  term.setCursorPos(1,1)
  print("=== Entry Method ===")
  print("1) PIN / Code")
  print("2) Card Token")
  write("> ")
  local choice = trim(read())

  term.clear()
  term.setCursorPos(1,1)
  if choice == "2" then
    print("Enter Card Token:")
    write("> ")
    return read()
  end

  print("Enter PIN:")
  write("> ")
  return read("*")
end

local function sendVerify(tag, code)
  local server = config_util.findServer(PROTOCOL, SERVER_NAME)
  if not server then return nil, "Server offline." end

  rednet.send(server, {
    type="verify",
    tag=tag,
    code=code
  }, PROTOCOL)

  local id, msg = rednet.receive(PROTOCOL, REQUEST_TIMEOUT)
  if not id then return nil, "No response." end
  if msg.type ~= "verify_result" then return nil, "Bad response." end

  return msg.ok, msg.reason
end

---------------------------------------------------
-- DOOR SELECTION MENU
---------------------------------------------------
local function pickDoor()
  local list, err = getDoorList()
  if not list then
    term.clear()
    term.setCursorPos(1,1)
    print("Error loading doors:")
    print(err)
    sleep(1.5)
    return nil
  end

  if #list == 0 then
    term.clear()
    term.setCursorPos(1,1)
    print("No doors registered.")
    sleep(1.5)
    return nil
  end

  local sel = 1
  local maxVisible = 6

  local function draw()
    term.clear()
    term.setCursorPos(1,1)
    print("=== Select Door ===")
    print("W/S to move, Enter to choose")

    local start = math.max(1, sel - math.floor(maxVisible/2))
    local finish = math.min(#list, start + maxVisible - 1)

    for i=start, finish do
      term.setCursorPos(2, i - start + 4)
      if i == sel then
        if term.isColor() then term.setTextColor(colors.cyan) end
        print(" > "..list[i])
        term.setTextColor(colors.white)
      else
        print("   "..list[i])
      end
    end
  end

  while true do
    draw()
    term.setCursorPos(1, maxVisible + 6)
    write("Command: ")
    local c = read()

    c = string.lower(c)

    if c == "w" then
      if sel > 1 then sel = sel - 1 end
    elseif c == "s" then
      if sel < #list then sel = sel + 1 end
    elseif c == "" or c == "enter" then
      return list[sel]
    end
  end
end

---------------------------------------------------
-- MAIN LOOP
---------------------------------------------------
config_util.openModems()

while true do
  local door = pickDoor()
  if not door then
    term.clear()
    term.setCursorPos(1,1)
    print("No door selected.")
    sleep(1)
    goto continue
  end

  local code = askCredential()
  term.clear()
  term.setCursorPos(1,1)
  print("Sending…")

  local ok, err = sendVerify(door, code)

  term.clear()
  term.setCursorPos(1,1)
  print("=== Access Result ===")
  print("Door: "..door)
  print("")

  if err and ok == nil then
    print("Error: "..err)
  elseif ok then
    print("ACCESS GRANTED")
    print("Door opening…")
  else
    print("ACCESS DENIED"..(err and (" ("..err..")") or ""))
  end

  print("\nPress Enter…")
  read()
  ::continue::
end
