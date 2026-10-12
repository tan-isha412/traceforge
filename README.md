# TraceForge

USB forensic investigation and device trust analysis. A live agent on each monitored machine reports USB connect/disconnect events to a central server, which profiles devices, detects identity anomalies (rules + explainable ML), scores risk and device trust, tags findings with MITRE ATT&CK, keeps a tamper-evident evidence log, and groups related suspicious events into incidents. A React dashboard shows it all, behind investigator logins when they are switched on.

```
agent (Windows WMI events / Linux udev, libusb descriptors)
   --POST /events/ingest (X-API-Key)--> FastAPI --> PostgreSQL
                                          |-- fingerprint.py  structural fingerprint of the descriptor tree
                                          |-- rules.py        identity / descriptor / source-machine checks
                                          |-- ml_model.py     Isolation Forest + SHAP, out-of-range check
                                          |-- mitre.py        ATT&CK technique for each finding
                                          |-- risk.py         weighted score with recorded reasoning
                                          |-- trust.py        device trust from its whole history
                                          |-- correlate.py    incidents per machine, cases across machines
                                          '-- integrity.py    SHA-256 hash chain over every event
React dashboard <-- REST JSON + Bearer login (devices, trust, timelines, incidents, cases, audit log)
```

## Quick start (Docker, everything)

```bash
docker compose up -d --build
docker compose run --rm server python -m server.seed_synthetic_data --reset   # demo data + trained model
```

Dashboard: http://localhost:5173 · API docs: http://localhost:8000/docs. The server's agent key is `change-me` unless you set `API_KEY=...` in `.env` before `up` (do that for anything beyond a demo).

## Quick start (without Docker)

```bash
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
copy .env.example .env          # set API_KEY; DATABASE_URL=sqlite:///./traceforge.db if you have no PostgreSQL
.venv\Scripts\python -m server.seed_synthetic_data --reset
.venv\Scripts\uvicorn server.main:app --reload
cd frontend && npm install && npm run dev
```

To require investigator logins, set `AUTH_ENABLED=true` in `.env`, create the first admin and restart the server:

```bash
.venv\Scripts\python -m server.manage create-user admin --role admin
```

The seeder replays six weeks of normal usage, trains the ML model on it, then runs nine planted attack scenarios through the live pipeline: type-switching BadUSB device, serial cloning, behavioural burst, missing serial, plain unknown device, cross-machine spread, a model clone whose descriptor adds a keyboard interface, enumeration drift, and a programmable attack board (Digispark) typing as a keyboard.

## Live agent

Run on each monitored machine (Windows or Linux; other systems fall back to libusb polling):

```bash
set TRACEFORGE_SERVER=http://<server>:8000
set TRACEFORGE_API_KEY=<same as the server's API_KEY>
.venv\Scripts\python agent\agent.py
```

- **Events, not polling:** WMI instance creation/deletion events on Windows, the udev netlink socket on Linux.
- **Enumeration:** after a device appears the agent waits 1.5 s, recording which interfaces appear, in what order and how long enumeration took.
- **Real descriptors:** it then reads the device and configuration descriptors through libusb (`pyusb` + `libusb-package`, no driver changes needed): USB version, device class, every interface (class/subclass/protocol) and every endpoint (direction, transfer type, packet size).
- **Offline queue:** events carry the time the OS reported them. If the server is unreachable they are kept in `~/.traceforge/spool.jsonl` and retried every 10 s, in order, across restarts.
- On Linux, reading descriptors works as a normal user; seeing events needs no extra permissions.

**Tests**

```bash
.venv\Scripts\python -m pytest
```

**Detection quality** (about 2 minutes; uses an in-memory database and a temporary model, so your data is untouched)

```bash
.venv\Scripts\python -m server.evaluate --show-misses
```

Trains on four weeks of synthetic normal usage, measures false alarms on two held-out weeks, runs randomised labelled attack trials, and compares hybrid vs rules-only vs ML-only plus Isolation Forest vs One-Class SVM.

**Timezone**: everything is stored in UTC. `TIMEZONE` in `.env` (default `Asia/Kolkata`) defines "night" for the ML hour-of-day feature and the seeder; the dashboard shows times in the same zone (`VITE_TIMEZONE` to change it).

## How detection works

| Layer | Finding | Weight |
| --- | --- | --- |
| rule | `unknown_device` - never seen before | 25 |
| rule | `device_type_mismatch` - same identity, different declared type | 40 |
| rule | `serial_reuse_across_models` - serial belongs to a different VID/PID | 40 |
| rule | `descriptor_mismatch` - fingerprint or descriptor fields differ from this device's recorded profile | 35 |
| rule | `descriptor_model_mismatch` - new unit whose fingerprint matches no known unit of the model it claims | 35 |
| rule | `missing_serial` / `serial_format_mismatch` - differs from other units of the same model | 30 |
| rule | `programmable_hid_board` - a BadUSB-capable board (Digispark, Teensy, Flipper Zero, Arduino Leonardo/Micro) presenting a keyboard | 40 |
| rule | `blocklisted_device` - an investigator blocklisted this device | 60 |
| rule | `same_model_new_serial` - new unit of a model that was on this machine in the last 24 h, under a different serial (lookalike swap) | 10 |
| rule | `keystroke_injection` - a new keyboard typed at machine speed (typing report) | 60 |
| rule | `large_transfer` - a large copy to USB storage, by size or 10x its usual (at disconnect) | 35-50 |
| rule | `new_source_machine` - device never connected to this machine before (silenced for devices marked trusted) | 15 |
| ML | `behavioural_outlier` - Isolation Forest or One-Class SVM, explained with SHAP | 15-45 |
| ML | `unseen_behaviour` - a feature far outside anything in the training data | 30 |

**MITRE ATT&CK.** Every finding lists its technique (`server/detection/mitre.py`): T1200 Hardware Additions, T1036 Masquerading, T1059 Command and Scripting Interpreter for a "drive" that types, and T1091 Replication Through Removable Media for a device spreading across machines. Incidents roll these up. Behavioural ML findings are left unmapped, because an unusual pattern alone does not name a technique.

**Attack-board IDs are one weak signal.** VID and PID are firmware strings; tools like the Hak5 Key Croc copy the real keyboard's IDs by default. The structural fingerprint and the behavioural model are what catch a spoofed board.

**Structural fingerprint.** The server hashes the descriptor tree without VID, PID or serial (`server/detection/fingerprint.py`). Those identifiers are firmware strings anyone can set; the interface/endpoint layout follows from what the hardware does. Two genuine units of a model share a fingerprint, so a clone that copies a SanDisk's identity but also exposes a keyboard interface is caught even on its first connection.

**Behavioural features** (per connect, from the device's own history): time since the last connection and its ratio to this device's median gap, hour of day and distance from this device's usual hour, connections in the last hour and day, distinct machines, enumeration time relative to this device's median, and whether the interface enumeration order changed. Isolation Forest picks one random feature per split, so a single extreme feature can leave the overall score near normal; `unseen_behaviour` reports values more than one training-range beyond anything seen in training (or any change in a feature that never varied).

Score = 5 baseline + sum of weights, capped at 100. Levels: low < 25 <= medium < 50 <= high < 75 <= critical. Every factor is stored with its explanation, and ML findings carry their drivers (e.g. "time since last connection was 181x shorter than this device's historical baseline").

**Incidents and cases.** A connection scoring 40+ opens an incident. Later events on the same machine join an active incident within 30 minutes if they involve a device already in it or are themselves suspicious; routine low-risk events are never dragged in. Disconnects inherit the score of the connection they close. Incidents on different machines within 24 hours that involve the same device, or a device presenting the same serial number, are grouped into a case. A device that has an open incident and then appears on another machine opens an incident there as well, even if that connection looks normal on its own. The dashboard shows the case and links its incidents. Investigators can set an incident to open / investigating / resolved and attach notes; resolved incidents stop collecting events.

## Device trust

Each device gets a trust score from 0 to 100 from its whole history (`server/scoring/trust.py`). It starts at 50, earns up to +30 for clean connections and up to +10 for time known, and loses half of its highest risk score in its last 30 days of activity plus 15 per unresolved incident. Levels: trusted (70+), suspicious (40-69), untrusted (below 40). A new device starts untrusted and earns trust. Every factor is returned with its reason.

Investigators can override it (`PUT /devices/{id}/trust`, or the buttons on the device profile):
- **Trusted** (allowlist) silences `new_source_machine` for a device that legitimately moves between machines; clone, descriptor and behaviour checks still apply.
- **Blocklisted** sets trust to 0, adds `blocklisted_device` on every connection and keeps the device out of ML training.

Nothing is blocked on the machine: TraceForge is an investigation platform, not a block/allow agent.

## Evidence integrity

Every event stores `record_hash = SHA-256(prev_hash + its canonical evidence)`, so all events form one hash chain (`server/integrity.py`). Editing, deleting or reordering any stored event breaks every hash after it. `GET /integrity/verify`, also shown in the dashboard header, says whether the chain is intact and names the first altered event. Databases created before this feature are chained at startup. Forensic exports carry each event's hash and the chain head, and send `X-Content-SHA256` for the exact file, which the dashboard shows after a download.

## Logins, roles and audit log

Off by default (`AUTH_ENABLED=false`) for local development. When on:

| Who | Can |
| --- | --- |
| any signed-in user | read devices, incidents, timelines, stats and evidence integrity |
| `investigator` | also change incident status and notes, and device trust |
| `admin` | everything, plus retraining, creating users (`POST /auth/users`) and the audit log |
| agents (API key) | send events; scripts with the key may also retrain |

Passwords are salted PBKDF2-SHA256. Bearer tokens are random, last 12 hours and are stored only as SHA-256. The audit log (`GET /audit`, the admin's Audit log tab) records sign-ins (including failed ones), sign-outs, incident changes, trust changes, retraining and user creation.

## Attack graph and incident replay

The **Attack graph** tab shows which devices touched which machines in the last 1, 7 or 30 days, with each link coloured by the worst risk seen on it. **Replay attack** on any incident plays its whole cross-machine case in time order (play/pause, slider, 1x/3x/8x), lighting machines up as the attack reaches them, with each step's findings and ATT&CK techniques. API: `GET /graph?days=7` or `GET /graph?incident_id=3`.

## Importing evidence from seized machines

Investigate a computer that never ran the agent, from the USB history its operating system already keeps (**Evidence import** tab, `POST /evidence/import`, or the command line):

```bash
.venv\Scripts\python -m server.manage import setupapi.dev.log --machine SEIZED-LAPTOP --registry usb.reg --timezone Asia/Kolkata
.venv\Scripts\python -m server.manage import kern.log --timezone Asia/Kolkata --dry-run
```

| Source | How to get it | What it gives |
| --- | --- | --- |
| `C:\Windows\INF\setupapi.dev.log` | copy from the machine or disk image | each USB device's first install, with its time and serial |
| Registry export | `reg export HKLM\SYSTEM\CurrentControlSet\Enum\USB usb.reg` | every device ever enumerated, with its name and driver (no times); fills in device types |
| Linux kernel log | `journalctl -k -o short-iso > kern.log`, `/var/log/syslog`, `kern.log` | connects and disconnects with serial, storage and keyboard detection |

Imported events go through the same rules, ML, trust, incidents and evidence chain as live ones. Each file is recorded with its SHA-256 (chain of custody) and cannot be imported twice; events the agent already reported are skipped. setupapi and syslog times are local, so give the seized machine's time zone.

## Plain-English incident stories

Every incident opens with **What happened**: a headline naming the kind of attack, what happened first, how it spread (with the gaps between machines), why it scored what it did, the behavioural model's reasons, ATT&CK techniques, trust and status, and recommended next steps (`GET /incidents/{id}/story`). It is written from templates on purpose: every sentence comes from stored evidence, so it is reproducible and never states what the evidence does not show.

## Keystroke injection (typing speed)

When a new device presents a keyboard, the agent records **when** its keys go down for 30 seconds and reports only timing statistics (count, rate, gaps, regularity); key codes are never read. People type with roughly 80-250 ms between keys and a lot of variation; `keystroke_injection` (+60) fires for 15+ keys at 25+ keys/s, or a median gap under 30 ms with almost no variation. Backends: python-evdev on Linux (the agent needs the `input` group), the Raw Input API on Windows. Set `TRACEFORGE_WATCH_TYPING=0` on the agent to turn it off.

## Data exfiltration watch

While a storage device is attached, the agent samples the OS's per-disk I/O counters (`/sys/block/*/stat`, WMI disk counters) and sends the bytes written and read with the disconnect; no file names or contents are read. `large_transfer` (T1052.001 Exfiltration over USB) fires for a copy of `EXFIL_THRESHOLD_MB` (default 500) or 10x the device's usual, scoring higher outside working hours.

## Model health

`GET /ml/drift` and the **Model health** tab compare recent normal activity with the training baseline using the Population Stability Index per feature (under 0.10 stable, 0.10-0.25 shifting, over 0.25 drifted), check the recent outlier rate against the expected ~3%, and say whether the model is healthy, should be watched, or should be retrained, and why.

## ML training

- `ML_ALGORITHM=iforest` (default) or `ocsvm` picks the live detector; a saved model trained with the other algorithm is ignored.
- Connections that became part of an incident, and everything from blocklisted devices, are left out of the training rows, so attacks are never learned as normal. `/ml/status` reports how many were left out and when the model was trained.
- `RETRAIN_INTERVAL_HOURS` retrains on stored history in the background; `0` (default) means only when `POST /ml/train` is called.

## Configuration

| Setting | Default | Purpose |
| --- | --- | --- |
| `DATABASE_URL` | PostgreSQL in Docker | or `sqlite:///./traceforge.db` |
| `API_KEY` | none | shared secret agents send as `X-API-Key` |
| `API_KEY_HASH` | none | store only the key's SHA-256 instead (`python -m server.manage hash-key`) |
| `AUTH_ENABLED` | `false` | investigator logins and roles |
| `CORS_ORIGINS` | `http://localhost:5173,http://127.0.0.1:5173` | browser origins allowed to call the API |
| `ML_ALGORITHM` | `iforest` | `iforest` or `ocsvm` |
| `RETRAIN_INTERVAL_HOURS` | `0` | scheduled retraining |
| `TIMEZONE` | `Asia/Kolkata` | what "night" means, and the zone the dashboard shows |
| `EXFIL_THRESHOLD_MB` | `500` | a copy this large to USB storage is flagged |

## Measuring the ML model

```bash
python -m server.detection.evaluate
```

Simulates ten weeks for 40 devices with their own habits, trains on weeks 1-7, and tests on weeks 8-10 plus 40 injected behavioural attacks of each type (identity and descriptor unchanged, so no rule can see them). Result with the default seed:

| | original 4 features | 9 features | 9 features + out-of-range check (what runs) |
| --- | --- | --- | --- |
| burst | 100% | 100% | 100% |
| off-hours | 2% | 98% | 98% |
| slow enumeration | 0% | 0% | 100% |
| enumeration order change | 0% | 0% | 100% |
| machine hopping | 100% | 100% | 100% |
| false positive rate | 3.3% | 3.3% | 3.3% |
| F1 | 0.54 | 0.70 | 0.95 |

These are simulated numbers: they show what each detector can separate, not accuracy on real fleets. Once real agents have reported a few weeks of data, retrain on it with `POST /ml/train`.

## API

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/events/ingest` | agent pushes a USB event (needs `X-API-Key` when a key is configured) |
| GET | `/devices?q=&risk_level=&known=&trust_level=`, `/devices/{id}` | profiles with latest risk and trust, search and filtering |
| PUT | `/devices/{id}/trust` | set `auto`, `trusted` or `blocklisted`, with an optional note (investigator) |
| GET | `/devices/{id}/timeline` | chronological events with anomalies |
| GET | `/devices/{id}/export?format=json\|csv` | export complete forensic investigation dossier (JSON/CSV) |
| GET | `/anomalies?device_id=&source=` | flagged anomalies with explanations |
| GET | `/risk-scores/{device_id}` | score history with reasoning |
| GET | `/incidents`, `/incidents/{id}` | correlated incidents, with their cross-machine case |
| PATCH | `/incidents/{id}` | set status (`open`, `investigating`, `resolved`) and/or note (investigator) |
| GET | `/integrity/verify` | check the evidence hash chain |
| GET | `/stats`, `/ml/status` | dashboard counters, model state |
| POST | `/ml/train` | retrain the model on stored history (admin login or `X-API-Key`) |
| GET, POST | `/auth/config`, `/auth/login`, `/auth/logout`, `/auth/me`, `/auth/users` | logins and user management |
| GET | `/audit?actor=&action=` | audit log (admin) |
| GET | `/graph?days=`, `/graph?incident_id=` | attack graph, or one case's events for replay |
| GET | `/incidents/{id}/story` | plain-English account with next steps |
| POST, GET | `/evidence/import`, `/evidence/imports` | import seized-machine USB history (investigator); the import record |
| GET | `/ml/drift?days=` | model health and drift per feature |

Run the tests with `python -m pytest`.

## Known limits

- No HTTPS of its own: put the server behind a TLS reverse proxy before using logins or keys outside a lab network.
- One API key is shared by all agents; a single machine's key cannot be revoked on its own.
- Ingestion chains one event at a time under an in-process lock, so run a single server process.
- The evidence chain detects edits, deletions and reordering. Removing only the newest events is caught by comparing against a chain head noted earlier (every forensic report prints it).
- The ML model has only been trained and measured on simulated data here. Retrain on real history before trusting its thresholds.
- Windows WMI events are checked by the WMI service about once a second, so a connect can be reported up to ~1 s late (Linux udev events are immediate).
- On Windows, interface nodes do not name their parent, so they are matched to the new device by VID/PID during the settle window.
- If libusb cannot open the device list (no backend), the agent still reports the event, with the OS fields only and no fingerprint; the dashboard says so.
- Trust on first use: a device that is anomalous the first time but keeps reconnecting becomes "known" afterwards. In the evaluation this is the only miss (a repeated serial-less clone).
