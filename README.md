# 🛡️ DoorAuth
### *A Complete Multi-Device Door Authentication & Security System for CC:Tweaked*
#### Keypads • Door Controllers • Auth Server • Admin Remote • Door Fob • Lockdown Alarm • Per-User Accounts • Card Tokens • Audit Logs

## 📌 Overview
DoorAuth is a fully modular, distributed access-control system for CC:Tweaked. A central server manages:

- Per-door PIN lists (salted hashes, not plaintext)
- Per-user accounts: a hashed access code and/or a magnetic card token, each with its own per-door entitlements
- Controller registration (authenticated with a shared secret, not open to any computer)
- Remote admin commands over a challenge/salt login, with replay protection
- Failed-attempt lockout on both door verification and admin login
- Audit logging
- Global lockdown mode, with an optional physical alarm client
- Client heartbeat monitoring
- Shared, interactive JSON configuration for every script

All clients (keypads, controllers, pocket apps) are stateless - all credentials, lockouts, and lockdown state live on the server.

## 🧠 System Architecture
DoorAuth consists of **seven programs** plus one shared library:

### 1. `config_util.lua` (shared library, not run directly)
Every other script loads this with `os.loadAPI("config_util.lua")`. It provides:
- A shared `doorauth_config.json`, sectioned by script name, with a 3-second "press any key to edit settings" startup prompt and a numbered field-edit menu
- Salted secret hashing (`hashSecret`/`checkSecret`) and token generation (`newToken`), used for the admin PIN, per-door PINs, per-user codes, card tokens, and session/controller keys
- Shared `openModems`/`findServer`/`trim`/`jsonEncode`/`jsonDecode`/`readAll`/`writeAll` helpers

> **This file must be copied to every computer** running any other DoorAuth script.

### 2. Auth Server (Core Brain) — `auth_server.lua`
- Stores door PINs (salted hashes) and per-user accounts (hashed code + optional card token + per-door entitlements)
- Verifies all PIN/code/card attempts, in this order: lockdown → lockout → card token → user code → legacy door PIN
- Locks out repeated failed attempts (per-door+sender, and door-wide) with exponential backoff
- Handles admin login via a challenge/salt round trip, with a freshness window and replay-cache to reject reused login signatures, plus its own lockout
- Authenticates controller registration with a shared secret, and signs `open` commands to controllers with a per-controller key + nonce
- Global lockdown mode, persistent audit logs, heartbeat monitoring, autosave

### 3. Door Controllers (Per-Door Redstone Units) — `door_controller.lua`
- Registers to the auth server using the shared registration secret
- Only pulses redstone for an `open` message that comes from the registered server ID **and** carries a fresh, correctly-signed nonce - a forged open sent by an arbitrary computer that merely knows the door's tag is rejected
- Auto-reconnect, heartbeat response

### 4. Keypad Computers (Touchscreen Entry Terminals) — `keypad_door.lua`
- Touchscreen numeric keypad, masked PIN entry
- Optional magnetic-card reader support (same wire message either way - the server decides what the credential resolves to)
- On-screen lockdown banner via periodic status polling
- Server-side verification, auto-reconnect

### 5. Pocket Admin Remote (Secure Admin Console) — `admin_remote.lua`
- Challenge/salt login, auto-renewing session tokens
- **Doors** menu: add/remove PINs, door open-time, remove door
- **Users** menu: add/remove users, set/clear codes, issue/clear magnetic cards (writes and verifies a physical card if a manipulator peripheral is attached, otherwise prints the token), enable/disable per-door access, clone access between users, search
- **Security** menu: remote door open, lockdown on/off
- Audit log viewer

### 6. Lockdown Alarm — `lockdown_alarm.lua`
- Polls the server for lockdown state and drives a redstone output (or all sides) to match
- **Fails closed**: if it can't reach the server, the alarm output turns **on** rather than silently going quiet

### 7. Door Fob (Player Access Device) — `door_fob.lua`
- Auto-discovers doors from the server
- Choice of typed PIN/code or a typed card-token (pocket computers generally don't have a card-manipulator peripheral)
- Lightweight & portable

### `doorauth_api_example.lua` (optional library)
Loadable with `os.loadAPI("doorauth_api_example.lua")` for scripting the admin API directly: `login(pin)`, then `listUsers`/`addUser`/`issueCard`/`lockdown`/etc., with the same auto-renewing session as `admin_remote.lua`.

## ⚙️ Hardware Support
- Regular computers
- Advanced computers
- Computers with monitors
- Wired/Wireless modems
- Pocket computers
- A card-reader/writer peripheral (optional, for magnetic-card credentials)

## 📦 Included Files
config_util.lua (shared library)
auth_server.lua
door_controller.lua
keypad_door.lua
door_fob.lua
admin_remote.lua
lockdown_alarm.lua
doorauth_api_example.lua (optional)

## 🚀 Installation
1. Copy `config_util.lua` onto **every** computer that will run any other DoorAuth script.
2. Install the relevant program(s) on each device.
3. Run each script once - within 3 seconds, press any key to open its setup menu and adjust values (door tag, redstone side, protocol name, etc.), or let it auto-start with defaults.
4. On `auth_server.lua`'s first run, set the admin PIN when prompted.
5. Set the **same** `registration_secret` in `auth_server`'s config and in every `door_controller`'s config - this is what stops an arbitrary computer from registering itself as a door controller. Change it from the default.
6. Attach modems and wiring; reboot all devices.

## 🧪 Testing Procedure
1. Start the auth server
2. Start door controllers and confirm they register (a mismatched `registration_secret` will show `register_denied`)
3. Start keypads / fobs
4. Log in via `admin_remote.lua`, add a door PIN and/or a user with a code, test both
5. Issue a user a card token (with or without a card manipulator attached) and test it
6. Trigger a lockout by entering a wrong code repeatedly, confirm it clears after the configured window
7. Lockdown test, including the `lockdown_alarm.lua` client if used
8. Check audit logs

## 🔐 Security Model
- The server holds all credentials as salted hashes (or, for card tokens, hashed against a server-wide pepper for O(1) lookup) - nothing is stored or sent as plaintext at rest
- Admin login uses a challenge/salt exchange with a freshness window and a replay cache, so a sniffed login exchange can't be replayed
- Repeated failed door or admin login attempts are rate-limited and temporarily locked out (exponential backoff)
- Controller registration requires a shared secret; door-open commands are addressed to a specific registered server ID and signed with a per-controller key + nonce
- Existing installs are migrated automatically: a legacy plaintext door-PIN database is hashed in place on first load after upgrading, and a legacy admin PIN hash is upgraded the first time you log in with it locally

**Honesty note:** the hashing in `config_util.lua` is a salted, multi-lane mixing hash designed to run in CC:Tweaked's Lua 5.1 sandbox (no confirmed bitwise-operator support, no OS-level CSPRNG) - it is meaningfully stronger than a bare rolling hash, but it is **not** a cryptographic primitive suitable outside this game's threat model.

## 🤝 Contributing
PRs welcome!

## 📄 License
MIT License recommended.
