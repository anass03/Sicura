# Sicura — Embedded Software for IoT

## Overview
**Sicura** is an end-to-end *Embedded Software for IoT* access-control system that integrates an **embedded Arduino node**, **MQTT messaging**, a **web dashboard/API**, and **Telegram-based approvals**.

**IoT runtime path (real system):**
- An **Arduino Uno R4 WiFi** runs a finite-state firmware (UI + authentication logic) using **I2C LCD**, **4x4 keypad**, **LEDs**, and a **buzzer** (timer-driven feedback).  
- The Arduino talks to a central **MQTT broker** over Wi-Fi:
  - publishes access requests (`accesso/richiesta`)
  - receives OTP/decisions (`accesso/decisione`)
  - handles enroll/delete/user sync (`accesso/utenti`)
- A **Node/Express backend** subscribes/publishes on the same MQTT topics, implements **admin/user management**, **JWT-protected APIs**, **OTP lifecycle**, logging, and triggers **Telegram notifications** (2FA-style approval and commands).
- The **web dashboard** (served by Express) provides user monitoring, enrollment/deletion, access decisions and system status; it is also exposed publicly via **cloudflared** under the `sicura.click` domain.

**Security & networking lab (SDN):**
- In parallel, an **SDN firewall lab** (Kathará + Open vSwitch + Ryu/OpenFlow 1.3) demonstrates **MQTT traffic protection** (default-drop, allowlist, scan/DoS detection) and exposes a **Ryu REST API**.
- The dashboard can control/inspect SDN rules and events through this REST API (via host proxy/forwarding).  
> Note: the SDN lab currently protects the MQTT broker inside the emulated topology; if the Arduino is outside that topology, its real MQTT traffic is not filtered inline by the SDN firewall.


## Requirements
- **Hardware**: Arduino Uno WiFi, face-recognition module (FM225-style), 16x2 I2C LCD, 4x4 keypad, breadboard, LEDs (green/yellow/red), buzzer, resistors, jumpers.
- **Software**:
  - Arduino IDE/CLI with `LiquidCrystal_I2C`, `ArduinoMqttClient`, keypad support; set SSID/PSK and broker in `arduino/main/arduino_to_server.cpp`.
  - Node.js 18+ and npm (`server/` backend + dashboard).
  - MQTT broker (Mosquitto) on TCP 1883 by default; topics `accesso/richiesta`, `accesso/decisione`, `accesso/utenti` are used for requests/decisions/user updates. TLS optional via `MQTT_URL` + CA.
  - Kathará + Docker, Open vSwitch, Ryu (OpenFlow 1.3) for the SDN lab.
  - Python 3 for `ngn-sdn-firewall/ryu_host_proxy.py`.

## Project Layout
```text
.(repo root)
├── arduino/main/                             # Arduino firmware
│   ├── main.ino                              # state machine + MQTT loop
│   ├── hardware.{h,cpp}                      # LCD, LEDs, buzzer timer ISR
│   ├── keypad_step.{h,cpp}                   # keypad input + PIN check
│   ├── arduino_to_server.{h,cpp}             # WiFi/MQTT connect + publish requests
│   ├── server_to_arduino.{h,cpp}             # subscribe decisions/enroll/delete
│   ├── faceID.{h,cpp}                        # Serial1 face module protocol
│   └── state.h
├── server/                                   # Node/Express backend + dashboard
│   ├── server.js                             # app entry, CORS, static pages
│   ├── config.js                             # MQTT URL/CA path, JWT secret, Ryu base
│   ├── public/                               # index.html, firewall.html assets
│   ├── routes/                               # authRoutes, accessRoutes, firewallRoutes, labRoutes
│   ├── services/                             # accessService, mqttService, telegramService, otpStore, userStore, labManager, etc.
│   ├── middleware/                           # authMiddleware, hostMiddleware
│   ├── data/                                 # users.json, otp.json, accessLog.json
│   └── package.json
├── ngn-sdn-firewall/                         # Kathará + Ryu lab
│   ├── lab.conf, *.startup                   # node wiring
│   ├── ctrl/, h_mqtt/, h_tools/              # Dockerfiles for controller/MQTT/tools
│   ├── shared/                               # sdn_firewall.py, firewall_logic.py, firewall_api.py, of_helpers.py
│   ├── ryu_host_proxy.py                     # host HTTP proxy → controller
│   └── tests/                                # artifacts, run_test.sh
├── tools/forward-ryu.sh|forward-ryu-stop.sh  # host port-forward helper to Ryu
├── slides/presentation.pptx                  # course presentation placeholder
└── README.md
```

## Embedded Hardware (Prototype)
| Component | Purpose | Interface/Pins | Polling or Interrupt | Notes |
| --- | --- | --- | --- | --- |
| Arduino Uno WiFi | Main controller + WiFi/MQTT client | UART (Serial1) to face module; I2C to LCD; GPIO A0-A3 LEDs/buzzer; D2-D9 keypad | Mixed: buzzer uses timer interrupt; others polling | WiFi via `WiFiS3`, MQTT via `ArduinoMqttClient` |
| 16x2 I2C LCD | User prompts / status | I2C (LiquidCrystal_I2C addr 0x27) | Polling | Cleared/redrawn on state changes |
| 4x4 Keypad | User PIN entry and commands | GPIO rows 9,8,7,6 + cols 5,4,3,2 | Polling via `Adafruit_Keypad.tick()` | Triggers PIN submit (#) or unlock (*) |
| Face recognition module | Primary identity check | UART `Serial1` | Polling (serial read loop) | Custom protocol (enroll, delete, unlock, notes) |
| LEDs (G/Y/R) | Status / alarms | A0, A1, A2 | Polling | Set per state/decision |
| Buzzer | Acoustic feedback | A3 + timer ISR | **Interrupt** (1ms timer with `FspTimer`) | Sequences driven by ISR + `tone()` |
| Breadboard, resistors, jumpers | Wiring and debouncing | N/A | N/A | Used to mount keypad/LEDs/buzzer safely |

<img src="images/Foto%2022-01-26,%2021%2019%2054.jpg" alt="Hardware prototype" width="640">

## Firmware (Arduino / C/C++)
- **Architecture**: Finite-state loop (`currentState` in `main.ino`) switching between `SERVER_TO_ARDUINO` (waiting for decisions/enroll/delete), `ARDUINO_TO_SERVER` (publishing access requests), and `KEYPAD_STEP` (PIN entry). State transitions happen when `currentState` changes; each state has `*_init` + `*_loop`.
- **Component flow**: LCD shows prompts; keypad collects PIN; face module on Serial1 handles unlock/enroll/delete; LEDs/buzzer provide feedback; MQTT drives access/OTP flows.
- **WiFi/MQTT**: `connettiWiFi()` + `connettiMQTT()` (blocking reconnect loops). MQTT topics: `accesso/richiesta` (publish JSON with `telegramUsername`), `accesso/decisione` (subscribe to decisions/OTP), `accesso/utenti` (subscribe to enroll/delete actions and results). Reconnect strategy: loop checks `mqttClient.connected()` and re-calls `connettiMQTT()`; `mqttClient.poll()` is invoked in main loop and inside `smartDelay`.
- **Face recognition**: `faceID.cpp` implements FM225-style binary protocol over `Serial1` (messages: enroll `0x1D`, delete `0x20`, unlock `0x12`, ping `0x02`, notes). User table (`userTable`) is maintained locally for UID/name mapping and deletion.
- **Keypad/LCD**: `keypad_step.cpp` polls keypad events; `#` validates PIN against OTP in `password[]`; `*` triggers unlock/verification. LCD text updated only on change (`showIfChanged`) to reduce flicker.
- **Buzzer timer**: `hardware.cpp` sets a 1ms periodic timer via `FspTimer` (`initBeepTimer` → `timer_callback`). ISR updates beep sequence; `handleBuzzer()` applies `tone()`/`noTone()` in loop. LEDs/buzzer are otherwise driven by polling functions.
- **MQTT messaging logic**:
  - Access request: after face unlock (`faceID.cpp` sets `user_name`), `arduino_to_server.cpp` publishes JSON to `accesso/richiesta`.
  - Decision handling: `server_to_arduino.cpp::messageReceived` checks payload for `OK` → loads OTP into `password[]` and moves to `KEYPAD_STEP`; `KO` sets denial; `START_ENROLL`/`DELETE` propagate to face module and respond on `accesso/utenti` with `ENROLL_RESULT`/`DELETE_RESULT`.
  - Unknown faces: result code 8 sets `user_name="unknownuser"` and requests admin approval.
- **Polling vs Interrupt (verified)**: Timer interrupt used **only** for the buzzer (`initBeepTimer` with `FspTimer`, ISR `timer_callback`). LCD, keypad, face module, LEDs all use polling in the main loop (`keypad.tick()`, `mqttClient.poll()`, `readFM225()` with blocking reads); no `attachInterrupt` or other ISRs found.

## Server (Node/Express)
- Serves static dashboard pages from `server/public` and APIs under `/api`. CORS allows `https://dashboard.sicura.click` (cloudflared tunnel → sicura.click domain was used to expose the dashboard).
<img src="images/Foto%2005-01-26,%2010%2048%2050.webp" alt="Cloudflared exposure" width="420">

- **Auth & sessions**:
  - `/api/auth` (`authRoutes.js`): admin registration/login with bcrypt-hashed password, JWT issuance (`jsonwebtoken`) signed with `JWT_SECRET`, brute-force throttling in-memory, single-session enforcement via `sessionId`. Admin status endpoint (`/admin-status`).
  - `authMiddleware.js`: `requireAdmin` verifies Bearer JWT, role `admin`, enabled flag, and session id.
- **Access control domain**:
  - `/api/status`, `/api/decision`, `/api/otp/regenerate`, `/api/users`, `/api/pending`, `/api/pending-deletes` (`accessRoutes.js`) require admin. Decisions `OK/KO` for unregistered/disabled users; OTP regeneration; start face enrollment (`START_ENROLL`); enable/disable users; trigger delete (propagated to Arduino).
  - Persistence in `server/data/`: `users.json` (admins/users, telegram usernames/chat IDs, enabled flags), `otp.json` (shared OTP), `accessLog.json` (recent access decisions, rotated to 7 days).
  - `accessService.js`: orchestrates requests from Arduino, decides routing (web vs Telegram), pushes MQTT decisions, manages OTP lifecycle, pending enroll/delete flows, writes logs.
- **MQTT bridge**:
  - `mqttService.js`: connects to `MQTT_URL` (plain TCP in code; TLS path `MQTT_CA_PATH` exists but is unused, mqtt is protected by the FIREWALL), subscribes `accesso/richiesta` and `accesso/utenti`, publishes `accesso/decisione` and user updates.
  - `telegramService.js`: Telegram bot (token from `TELEGRAM_TOKEN`) handles `/start` to link chats, `/yes` `/no` to approve/deny; notifies admin or user on requests and OTP changes.
  - `otpStore.js` (not shown above) stores current OTP on disk; `userStore.js` normalizes Telegram usernames, saves admins/users, enforces uniqueness, links chats.
- **Firewall + lab control**:
  - `/api/ui/firewall/*` (`firewallRoutes.js`): proxy to Ryu REST (`RYU_API_BASE` env) with fallbacks to `127.0.0.1:18080` and management IP `10.0.0.1:8080`.
  - `/api/ui/lab/start|stop` (`labRoutes.js`): start/stop Kathará lab via `labManager.js` (`kathara lstart --noterminals` / `lclean` in `ngn-sdn-firewall`).
  - `middleware/hostMiddleware.js` can restrict to localhost if wired.
- **Access model**: Admins manage users, OTP, and enrollment. Registered/enabled users approve/deny their own requests via Telegram; unregistered/disabled users fall back to admin approval or denial. JWT protects all admin APIs; dashboard uses the token for firewall/lab calls.

## Security (Cross-Cutting)
- **TLS/certificates**: `config.js` points to `mosq-certs/mqtt_ca.crt`, but `mqttService.js` connects with plain `mqtt.connect(MQTT_URL)`; TLS is planned/partially scaffolded but not enforced in current code; security relies on network isolation/SDN lab. Browser side served over HTTPS via cloudflared (sicura.click) but backend listens plain HTTP:3000.
- **JWT auth**: Issued in `authRoutes.js` with role `admin` and session id; verified in `authMiddleware.js` for every protected route (status, decision, user mgmt, firewall, lab). Missing/expired tokens return 401; non-admin 403.
- **SDN firewalling**: `ngn-sdn-firewall/shared/sdn_firewall.py` installs default-drop, proxy ARP gateways, and deterministic flows allowing MQTT (1883/8883) only from inside subnet `10.0.10.0/24`; blocks outside/scan/DoS (port-scan window 10s/6 ports, DoS 5s/160 pkts, SYN flood heuristics in `firewall_logic.py`), supports manual block/unblock IP/ports via REST.
- **Telegram bot**: Token comes from env `TELEGRAM_TOKEN`; chat IDs stored in `users.json`. Notifications trigger on access requests, OTP changes, registrations, `/yes` `/no` decisions. Bot commands only act if chat is linked to admin/user (`userStore` checks).
- **MQTT topics security**: No TLS/auth configured; topics are hardcoded and publicly readable inside the lab. OTP is included in `accesso/decisione` payloads; protect broker network with SDN rules.
- **Host proxy**: `ngn-sdn-firewall/ryu_host_proxy.py` forwards host HTTP to controller inside Kathará. No auth on the proxy itself; rely on localhost binding and JWT on the dashboard side to limit usage.

## SDN Firewall / Lab
- **Kathará topology**: `lab.conf` with nodes `ctrl` (Ryu REST 8080), `s1` (OVS), `h_mqtt` (Mosquitto), `h_client`/`h_out` (tooling). Deterministic MACs and gateway ARP proxying avoid learning flows.
- **Firewall logic**: Ryu app (`sdn_firewall.py`) installs static flows for inside/outside, table-miss drop, mirrors selected traffic, and enforces MQTT allowlist. Detection and blocklists are in `firewall_logic.py`; REST API exposed via `firewall_api.py` (`/api/firewall/status`, `events`, `block`, `unblock`, `block_port`, `unblock_port`).
- **Dashboard integration**: `firewallRoutes.js` proxies REST calls; `labRoutes.js` can start/stop the lab from the UI (dashboard “firewall page” buttons call these routes). `labManager.js` runs `kathara lstart/lclean` headless.
- **Host access**: Use `python3 ngn-sdn-firewall/ryu_host_proxy.py` (binds 127.0.0.1:18080) or `tools/forward-ryu.sh` (Docker socat) to reach controller from host; backend fallbacks include 127.0.0.1:18080, localhost:8080, and mgmt IP 10.0.0.1:8080.

## Environment setup (JWT, Telegram, TLS)
- **Secrets (required to start server)**:
```bash
export JWT_SECRET="change-me-to-a-strong-random-string"
export TELEGRAM_TOKEN="123456789:token-from-BotFather"   # create bot via @BotFather
```
Run `npm start` in the same shell (or add to your shell profile/systemd env).

- **TLS for MQTT (not in repo)**:
  - Create cert folder and place your CA cert as expected by `config.js`:
    ```bash
    mkdir -p server/mosq-certs
    cp /path/to/your/mqtt_ca.crt server/mosq-certs/mqtt_ca.crt
    ```
  - If your broker uses TLS, set `MQTT_URL` in `server/config.js` to `mqtts://<host>:<port>` and ensure the CA matches the broker cert. Self-signed example:
    ```bash
    # generate CA
    openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
      -keyout ca.key -out mqtt_ca.crt -subj "/CN=local-mqtt-ca"
    # generate broker cert signed by CA
    openssl req -new -nodes -newkey rsa:2048 -keyout broker.key -out broker.csr -subj "/CN=broker.local"
    openssl x509 -req -in broker.csr -CA mqtt_ca.crt -CAkey ca.key -CAcreateserial -out broker.crt -days 365
    # copy mqtt_ca.crt into server/mosq-certs/ as above and configure your broker with broker.crt/broker.key
    ```
  - Without TLS, leave `MQTT_URL` as `mqtt://host:1883` and omit the cert (current default).
- **TLS for the dashboard** (optional if you want HTTPS locally):
  - Generate a local cert (self-signed) and run a reverse proxy (nginx/traefik or `cloudflared tunnel`) terminating TLS:
    ```bash
    openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
      -keyout dashboard.key -out dashboard.crt -subj "/CN=localhost"
    ```
  - Configure your proxy to serve `https://localhost` → `http://127.0.0.1:3000`. Example nginx server block (drop into `/etc/nginx/sites-available/sicura` and enable):
    ```
    server {
      listen 443 ssl;
      server_name localhost;
      ssl_certificate     /path/to/dashboard.crt;
      ssl_certificate_key /path/to/dashboard.key;
      location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
      }
    }
    ```
  - For public exposure, use `cloudflared tunnel` (as used for sicura.click) or a proper certificate from a CA; keep `CORS` origin aligned with your HTTPS URL.

## Getting Started
1) **Backend & UI**
```bash
cd server
npm install
npm start    # http://localhost:3000 (CORS allows https://dashboard.sicura.click)
```

2) **SDN lab (requires Docker + Kathará)**
```bash
cd ngn-sdn-firewall
docker build -t ngn-sdn-firewall-ctrl -f ctrl/Dockerfile .
docker build -t ngn-sdn-firewall-mqtt -f h_mqtt/Dockerfile .
docker build -t ngn-host-tools -f h_tools/Dockerfile .
kathara lstart            # or use the dashboard “Start Lab” button (calls labRoutes)
python3 ryu_host_proxy.py # host proxy on http://127.0.0.1:18080
```
Stop/clean: `kathara lclean` or dashboard “Stop Lab”.

3) **Firewall reachability test (host)**
```bash
curl http://127.0.0.1:18080/api/firewall/status
```

4) **Arduino firmware**
- Open `arduino/main/main.ino` in Arduino IDE, install required libraries, select **Arduino Uno WiFi**, set SSID/PSK/MQTT broker in `arduino_to_server.cpp`, and upload via USB.
- Firmware auto-connects WiFi/MQTT, subscribes to decisions/enroll/delete, and publishes access requests.

## Firewall quick tests (lab)
- Status/events from host (after proxy/forward is up):
```bash
curl http://127.0.0.1:18080/api/firewall/status
curl "http://127.0.0.1:18080/api/firewall/events?limit=50"
```
- Manual block/unblock examples:
```bash
curl -X POST http://127.0.0.1:18080/api/firewall/block \
  -H 'Content-Type: application/json' \
  -d '{"ip":"10.0.10.30","seconds":90}'

curl -X POST http://127.0.0.1:18080/api/firewall/block_port \
  -H 'Content-Type: application/json' \
  -d '{"port":1883,"scope":"mqtt","seconds":120,"override_allow":false}'
```
- In-lab traffic tests (`kathara connect h_client` / `h_out`):
```bash
nc -vz 10.0.11.20 1883             # allowed from inside client
nmap -p 1800-1815 10.0.11.20       # triggers port-scan detection from outside
hping3 -S -p 1883 --faster 10.0.11.20   # DoS detection example
```

## References / Documentation
- Telegram bot API (node-telegram-bot-api): https://github.com/yagop/node-telegram-bot-api/blob/master/doc/usage.md#events
- Node.js: https://nodejs.org/en/docs
- Express: https://expressjs.com/en/guide/routing.html
- MQTT.js: https://github.com/mqttjs/MQTT.js#readme
- Arduino Uno R4 WiFi: https://docs.arduino.cc/hardware/uno-r4-wifi/
- ArduinoMqttClient: https://github.com/arduino-libraries/ArduinoMqttClient
- LiquidCrystal_I2C: https://github.com/johnrickman/LiquidCrystal_I2C
- Ryu controller: https://ryu.readthedocs.io/en/latest/
- Kathará network emulation: https://github.com/KatharaFramework/Kathara
- Open vSwitch: https://www.openvswitch.org/support/

## Links
- Presentation: `slides/presentation.pptx`
- Demo video (YouTube): https://youtu.be/OyNxdv6P7Q0?si=cZilz_sPnY5kkWRg

## Images
![Firmware flow and UI mock](images/Screenshot%20from%202026-01-24%2020-17-17.png)

![Firewall dashboard preview](images/Screenshot%20from%202026-01-24%2020-17-35.png)

## Team
| Name | Role | Main Contributions |
| --- | --- | --- |
| ANAS SOUSSANE | Backend / SDN / Embedded (MQTT) | Node/Express server + dashboard APIs, MQTT integration/bridge, SDN firewall lab (Ryu/OpenFlow + Kathará/OVS) and REST proxy/forwarding, Arduino MQTT/Wi-Fi logic, GitHub repository setup & maintenance |
| ANDREA DALLA VILLA | Embedded / Documentation | Arduino firmware (UI + hardware logic: LCD/keypad/FaceID flow/LEDs/buzzer handling), hardware assembly support, demo video, course presentation (slides) |
