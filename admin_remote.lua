-- admin_remote.lua (DOORS + USERS + SECURITY + LOG VIEW)
-- Pocket admin console. Login uses a challenge/salt round trip so the
-- signature scheme works against a salted admin PIN hash, and admin_cmd
-- calls transparently re-login once if the session token has expired.

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

local cfg = config_util.load("admin_remote", defaults, fields, "Admin Remote Config")

local PROTOCOL        = cfg.protocol
local SERVER_NAME      = cfg.server_name
local REQUEST_TIMEOUT  = cfg.request_timeout
---------------------------------

local trim = config_util.trim

---------------------------------------------------
-- UTILS
---------------------------------------------------
local function setColor(col)
  if term.isColor and term.isColor() then
    term.setTextColor(col)
  end
end

local function isPocketComputer()
  return pocket ~= nil
end

local function findCardWriter()
  for _, pname in ipairs(peripheral.getNames()) do
    local ok, p = pcall(peripheral.wrap, pname)
    if ok and p and type(p.hasCard) == "function" and type(p.writeCard) == "function" then
      return pname, p
    end
  end
  return nil
end

local function writeCard(reader, token, label)
  local waited = 0
  while not reader.hasCard() and waited < 20 do
    sleep(0.5)
    waited = waited + 0.5
  end
  if not reader.hasCard() then return false, "No card inserted." end

  local okWrite = pcall(reader.writeCard, token)
  if not okWrite then return false, "Write failed." end

  sleep(0.2)
  local okRead, readBack = pcall(reader.readCard)
  if not okRead or tostring(readBack) ~= token then
    return false, "Card verification failed."
  end

  if type(reader.setLabel) == "function" then pcall(reader.setLabel, label) end
  if type(reader.setSecure) == "function" then pcall(reader.setSecure, true) end
  if type(reader.ejectCard) == "function" then pcall(reader.ejectCard) end

  return true
end

---------------------------------------------------
-- LOGIN
---------------------------------------------------
local function loginWithPin(pin)
  local server = config_util.findServer(PROTOCOL, SERVER_NAME)
  if not server then return nil, "Server not found." end

  rednet.send(server, {type="admin_login_challenge"}, PROTOCOL)
  local id, msg = rednet.receive(PROTOCOL, REQUEST_TIMEOUT)
  if not (id==server and msg and msg.type=="admin_login_challenge_salt" and msg.salt) then
    return nil, "No challenge response."
  end

  local stamp = tostring(os.epoch("utc"))
  local sig = config_util.hash(config_util.hash(pin, msg.salt)..stamp, "")

  rednet.send(server, {type="admin_login", timestamp=stamp, sig=sig}, PROTOCOL)
  local id2, msg2 = rednet.receive(PROTOCOL, REQUEST_TIMEOUT)

  if id2==server and msg2 and msg2.type=="admin_login_ok" then
    return { token=msg2.token, pin=pin, startedAt=os.epoch("utc") }
  end

  local reason = msg2 and (msg2.reason or msg2.type) or "no_response"
  return nil, reason
end

local function login()
  term.clear()
  term.setCursorPos(1,1)
  print("=== DoorAuth Admin Remote ===")
  print("Enter Admin PIN:")
  local pin = read("*")

  local session, err = loginWithPin(pin)
  if not session then
    print("Login failed: "..tostring(err))
    sleep(1.2)
    return nil
  end

  sleep(0.4)
  term.clear()
  term.setCursorPos(1,1)
  return session
end

---------------------------------------------------
-- SEND ADMIN CMD (with one auto-relogin on expiry)
---------------------------------------------------
local function adminCmd(session, cmdTable)
  local server = config_util.findServer(PROTOCOL, SERVER_NAME)
  if not server then
    print("Server offline.")
    sleep(1)
    return nil
  end

  cmdTable.type="admin_cmd"
  cmdTable.token=session.token

  rednet.send(server,cmdTable,PROTOCOL)
  local _,msg=rednet.receive(PROTOCOL,REQUEST_TIMEOUT)

  if msg and msg.type=="admin_denied" and session.pin then
    local newSession = loginWithPin(session.pin)
    if newSession then
      session.token = newSession.token
      cmdTable.token = session.token
      rednet.send(server,cmdTable,PROTOCOL)
      _,msg = rednet.receive(PROTOCOL,REQUEST_TIMEOUT)
    end
  end

  return msg
end

---------------------------------------------------
-- LOG VIEWER (interactive scroll)
---------------------------------------------------
local function viewLogs(session)
  local msg = adminCmd(session, {cmd="logs"})
  if not msg or msg.type ~= "admin_logs" or type(msg.logs) ~= "table" then
    term.clear()
    term.setCursorPos(1,1)
    print("No logs or error fetching logs.")
    sleep(1.2)
    return
  end

  local logs = msg.logs
  if #logs == 0 then
    term.clear()
    term.setCursorPos(1,1)
    print("No log entries yet.")
    sleep(1.2)
    return
  end

  local maxVisible = 8
  local pos = math.max(#logs - maxVisible + 1, 1) -- start near newest

  local function draw()
    term.clear()
    term.setCursorPos(1,1)
    print("=== Audit Logs ("..#logs.." entries) ===")
    print("W/S = scroll, Q = back")

    local last = math.min(pos + maxVisible - 1, #logs)
    for i = pos, last do
      local e = logs[i]
      local lineY = 3 + (i - pos) + 1
      term.setCursorPos(1, lineY)

      local label = string.format("%4d %s %-14s", i, e.time or "??:??", e.event or "?")

      local tail = ""
      if e.tag then tail = tail .. " tag="..tostring(e.tag) end
      if e.ok ~= nil then
        tail = tail .. " "..(e.ok and "OK" or "FAIL")
      end
      if e.detail then
        tail = tail .. " "..tostring(e.detail)
      end

      local color = colors.white
      if e.event == "pin_attempt" then
        color = e.ok and colors.lime or colors.red
      elseif e.event == "door_open" or e.event == "remote_open" then
        color = colors.cyan
      elseif e.event == "lockdown_on" or e.event == "lockdown_off" then
        color = colors.orange or colors.yellow
      elseif e.event == "admin_login" then
        color = e.ok and colors.lime or colors.red
      end

      setColor(color)
      write(label.." "..tail)
      setColor(colors.white)
    end

    local footerY = maxVisible + 5
    term.setCursorPos(1, footerY)
    print(string.format("Showing %d-%d of %d", pos, last, #logs))
  end

  while true do
    draw()
    term.setCursorPos(1, maxVisible + 7)
    write("Command (W/S/Q): ")
    local inp = read()
    inp = string.lower(inp or "")

    if inp == "w" then
      if pos > 1 then pos = pos - 1 end
    elseif inp == "s" then
      if pos < math.max(#logs - maxVisible + 1, 1) then
        pos = pos + 1
      end
    elseif inp == "q" or inp == "" then
      break
    end
  end

  term.clear()
  term.setCursorPos(1,1)
end

---------------------------------------------------
-- DOORS MENU
---------------------------------------------------
local function doorsMenu(session)
  while true do
    term.clear() term.setCursorPos(1,1)
    print([[=== Doors ===

1) List Doors
2) Show Door
3) Add PIN
4) Delete PIN
5) Remove Door
6) Set OpenTime
7) Back
]])
    write("Choose: ")
    local c = read()

    if c=="1" then
      local msg=adminCmd(session,{cmd="list"})
      term.clear() term.setCursorPos(1,1)
      if msg and msg.doors then
        print("Doors:")
        for tag,data in pairs(msg.doors) do
          print(("%s (pins:%d, open:%s)"):format(tag,data.pinCount,data.openTime))
        end
      else
        print("No response.")
      end
      print("\nPress Enter…") read()

    elseif c=="2" then
      write("Door tag: ") local tag=read()
      local msg=adminCmd(session,{cmd="show",tag=tag})
      term.clear() term.setCursorPos(1,1)
      if msg and msg.door then
        print("Door:",tag)
        print("OpenTime:",msg.door.openTime)
        print("Pins:", msg.door.pinCount)
      else
        print("No such door.")
      end
      print("\nPress Enter…") read()

    elseif c=="3" then
      write("Door tag: ") local tag=read()
      write("New PIN: ") local pin=read()
      local msg=adminCmd(session,{cmd="add",tag=tag,pin=pin})
      term.clear() term.setCursorPos(1,1)
      print(msg and msg.ok and "Added." or "Already exists or error.")
      sleep(1)

    elseif c=="4" then
      write("Door tag: ") local tag=read()
      write("PIN to remove: ") local pin=read()
      local msg=adminCmd(session,{cmd="del",tag=tag,pin=pin})
      term.clear() term.setCursorPos(1,1)
      print(msg and msg.ok and "Removed." or "Not found or error.")
      sleep(1)

    elseif c=="5" then
      write("Door tag: ") local tag=read()
      adminCmd(session,{cmd="remove",tag=tag})
      term.clear() term.setCursorPos(1,1)
      print("Door removed.")
      sleep(1)

    elseif c=="6" then
      write("Door tag: ") local tag=read()
      write("Seconds: ") local sec=read()
      adminCmd(session,{cmd="opentime",tag=tag,seconds=sec})
      term.clear() term.setCursorPos(1,1)
      print("Updated.")
      sleep(1)

    elseif c=="7" or c=="" then
      return
    end
  end
end

---------------------------------------------------
-- USERS MENU
---------------------------------------------------
local function issueCardFlow(session)
  write("User name: ") local name = read()
  term.clear() term.setCursorPos(1,1)

  local msg = adminCmd(session, {cmd="user_card_issue", name=name})
  if not (msg and msg.ok) then
    print("Failed to issue card.")
    sleep(1.2)
    return
  end

  if isPocketComputer() then
    print("Pocket computers can't drive a card manipulator.")
    print("Token (write this down): "..msg.token)
    print("\nPress Enter…") read()
    return
  end

  local readerName, reader = findCardWriter()
  if not reader then
    print("No card manipulator found. Token: "..msg.token)
    print("\nPress Enter…") read()
    return
  end

  print("Insert a blank card into the manipulator...")
  local ok, writeErr = writeCard(reader, msg.token, name)
  if ok then
    print("Card written and verified for "..name..".")
  else
    print("Card write failed: "..tostring(writeErr))
    print("Rolling back issued token...")
    adminCmd(session, {cmd="user_card_clear", name=name})
  end
  print("\nPress Enter…") read()
end

local function usersMenu(session)
  while true do
    term.clear() term.setCursorPos(1,1)
    print([[=== Users ===

1)  List Users
2)  Show User
3)  Add/Update Code
4)  Remove User
5)  Enable Door For User
6)  Disable Door For User
7)  Show User's Doors
8)  Issue/Write Card
9)  Clear Card
10) Clear User Code
11) Clear All Doors
12) Clone Access From User
13) Search Users
14) Back
]])
    write("Choose: ")
    local c = read()

    if c=="1" then
      local msg=adminCmd(session,{cmd="user_list"})
      term.clear() term.setCursorPos(1,1)
      if msg and msg.users then
        for _,u in ipairs(msg.users) do
          print(("%s (doors:%d, code:%s, card:%s)")
            :format(u.name,u.doorCount,u.hasCode and "yes" or "no",u.hasCard and "yes" or "no"))
        end
      else
        print("No response.")
      end
      print("\nPress Enter…") read()

    elseif c=="2" then
      write("User name: ") local name=read()
      local msg=adminCmd(session,{cmd="user_show",name=name})
      term.clear() term.setCursorPos(1,1)
      if msg and not msg.notFound then
        print("User:",msg.name)
        print("Code set:",msg.hasCode)
        print("Card set:",msg.hasCard)
        print("Doors:", table.concat(msg.doors or {}, ", "))
      else
        print("No such user.")
      end
      print("\nPress Enter…") read()

    elseif c=="3" then
      write("User name: ") local name=read()
      write("New code: ") local code=read()
      local msg=adminCmd(session,{cmd="user_add",name=name,code=code})
      term.clear() term.setCursorPos(1,1)
      print(msg and msg.ok and "Code set." or "Failed.")
      sleep(1)

    elseif c=="4" then
      write("User name: ") local name=read()
      local msg=adminCmd(session,{cmd="user_del",name=name})
      term.clear() term.setCursorPos(1,1)
      print(msg and msg.ok and "User removed." or "Not found.")
      sleep(1)

    elseif c=="5" then
      write("User name: ") local name=read()
      write("Door tag: ") local tag=read()
      local msg=adminCmd(session,{cmd="user_enable",name=name,tag=tag})
      term.clear() term.setCursorPos(1,1)
      print(msg and msg.ok and "Enabled." or "Failed.")
      sleep(1)

    elseif c=="6" then
      write("User name: ") local name=read()
      write("Door tag: ") local tag=read()
      local msg=adminCmd(session,{cmd="user_disable",name=name,tag=tag})
      term.clear() term.setCursorPos(1,1)
      print(msg and msg.ok and "Disabled." or "Failed.")
      sleep(1)

    elseif c=="7" then
      write("User name: ") local name=read()
      local msg=adminCmd(session,{cmd="user_doors",name=name})
      term.clear() term.setCursorPos(1,1)
      if msg then
        print("Doors:", table.concat(msg.doors or {}, ", "))
      else
        print("No response.")
      end
      print("\nPress Enter…") read()

    elseif c=="8" then
      issueCardFlow(session)

    elseif c=="9" then
      write("User name: ") local name=read()
      local msg=adminCmd(session,{cmd="user_card_clear",name=name})
      term.clear() term.setCursorPos(1,1)
      print(msg and msg.ok and "Card cleared." or "Failed.")
      sleep(1)

    elseif c=="10" then
      write("User name: ") local name=read()
      local msg=adminCmd(session,{cmd="user_clear_code",name=name})
      term.clear() term.setCursorPos(1,1)
      print(msg and msg.ok and "Code cleared." or "Failed.")
      sleep(1)

    elseif c=="11" then
      write("User name: ") local name=read()
      local msg=adminCmd(session,{cmd="user_clear_doors",name=name})
      term.clear() term.setCursorPos(1,1)
      print(msg and msg.ok and "Doors cleared." or "Failed.")
      sleep(1)

    elseif c=="12" then
      write("Source user: ") local src=read()
      write("Target user: ") local dst=read()
      write("Copy code too? (yes/no): ") local inc=read()
      local includeCode = trim(inc):lower()=="yes" or trim(inc):lower()=="y"
      local msg=adminCmd(session,{cmd="user_clone",source=src,name=dst,includeCode=includeCode})
      term.clear() term.setCursorPos(1,1)
      print(msg and msg.ok and "Cloned." or "Failed.")
      sleep(1)

    elseif c=="13" then
      write("Search query: ") local q=read()
      local msg=adminCmd(session,{cmd="user_search",query=q})
      term.clear() term.setCursorPos(1,1)
      if msg and msg.names then
        for _,n in ipairs(msg.names) do print("- "..n) end
      else
        print("No response.")
      end
      print("\nPress Enter…") read()

    elseif c=="14" or c=="" then
      return
    end
  end
end

---------------------------------------------------
-- SECURITY MENU
---------------------------------------------------
local function securityMenu(session)
  while true do
    term.clear() term.setCursorPos(1,1)
    print([[=== Security ===

1) Remote Open Door
2) LOCKDOWN ON
3) LOCKDOWN OFF
4) Back
]])
    write("Choose: ")
    local c = read()

    if c=="1" then
      write("Door tag to open: ") local tag=read()
      local msg=adminCmd(session,{cmd="open",tag=tag})
      term.clear() term.setCursorPos(1,1)
      if msg and msg.ok then
        print("Door opened.")
      else
        print("Blocked (lockdown active or error).")
      end
      sleep(1)

    elseif c=="2" then
      adminCmd(session,{cmd="lockdown_on"})
      term.clear() term.setCursorPos(1,1)
      print("LOCKDOWN ENABLED")
      sleep(1)

    elseif c=="3" then
      adminCmd(session,{cmd="lockdown_off"})
      term.clear() term.setCursorPos(1,1)
      print("Lockdown disabled.")
      sleep(1)

    elseif c=="4" or c=="" then
      return
    end
  end
end

---------------------------------------------------
-- HELP
---------------------------------------------------
local function helpScreen()
  term.clear() term.setCursorPos(1,1)
  print([[=== DoorAuth Admin Help ===

Doors    - manage per-door PINs and open timing
Users    - manage per-user codes, card tokens, and door access
Security - remote open, lockdown on/off
Logs     - view the server's audit log

Sessions auto-renew using your PIN if they expire while
this program is running.
]])
  print("Press Enter…") read()
end

---------------------------------------------------
-- MAIN MENU
---------------------------------------------------
local function mainMenu(session)
  while true do
    term.clear()
    term.setCursorPos(1,1)
    print([[=== DoorAuth Admin ===

1) Doors
2) Users
3) Security
4) Logs
5) Help
6) Logout
]])

    write("Choose: ")
    local c=read()

    if c=="1" then doorsMenu(session)
    elseif c=="2" then usersMenu(session)
    elseif c=="3" then securityMenu(session)
    elseif c=="4" then viewLogs(session)
    elseif c=="5" then helpScreen()
    elseif c=="6" then
      term.clear() term.setCursorPos(1,1)
      print("Logged out.")
      sleep(0.4)
      term.clear() term.setCursorPos(1,1)
      return
    end
  end
end

---------------------------------------------------
-- ENTRY
---------------------------------------------------
config_util.openModems()

while true do
  local session=login()
  if session then mainMenu(session) end
end
