# TraceForge

USB forensic investigation and device trust analysis. A live agent on each monitored machine reports USB connect/disconnect events to a central server, which profiles devices, detects identity anomalies (rules + explainable ML), scores risk and device trust, tags findings with MITRE ATT&CK, keeps a tamper-evident evidence log, and groups related suspicious events into incidents. A React dashboard shows it all, behind investigator logins when they are switched on.

```
agent (Windows WMI events / Linux udev, libusb descriptors)
   --POST /events/ingest (X-API-Key)--> FastAPI --> PostgreSQL
                                          |-- fingerprint.py  structural fingerprint of the descriptor tree
                                          |-- rules.py        facts about each event, matched by Sigma rules
                                          |-- sigma.py        Sigma rule engine (rules in sigma_rules/*.yml)
                                          |-- ml_model.py     Isolation Forest + SHAP, out-of-range check
                                          |-- mitre.py        ATT&CK technique for each finding
                                          |-- nist.py         NIST SP 800-30 scales and risk matrix
                                          |-- risk.py         event and attachment risk, with recorded reasoning
                                          |-- trust.py        device trust from its whole history
                                          |-- correlate.py    incidents per machine, cases across machines
                                          |-- integrity.py    SHA-256 hash chain over every event
                                          '-- signing.py      RSA-PSS signatures on exports and attestations
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
- **Encrypted spool:** each queued event is sealed with AES-256-GCM under a key derived (HKDF-SHA256) from the agent's API key and hostname (`agent/spool.py`), written atomically and owner-only. Nobody with access to the monitored PC can read the queue, and a line that was edited fails GCM authentication: it is moved to `spool.jsonl.rejected` with a warning and never sent. Without an API key the spool stays plaintext (the agent says so).
- On Linux, reading descriptors works as a normal user; seeing events needs no extra permissions.
- On Linux, install the agent extras for the keystroke-timing watch: `pip install -r requirements-agent.txt` (adds `evdev`, which needs the kernel headers: `apt install linux-headers-$(uname -r)` or your distro's equivalent). Without it the agent still runs and skips that watch. Windows needs nothing extra.

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

Detection follows published standards rather than hand-picked points:

- **Rules are [Sigma](https://github.com/SigmaHQ/sigma-specification) rules**, the open, vendor-neutral format SIEMs (Splunk, Elastic, QRadar, Wazuh) use. Each is a YAML file in `server/detection/sigma_rules/` with the standard fields: title, UUID, status, description, references, author, date, logsource, detection, false positives, **level** and ATT&CK **tags**. `server/detection/sigma.py` loads and checks them at startup and matches them against each event. Facts that need history ("this identity was recorded as a flash drive") are worked out first in `rules.py` and matched as fields, the way a SIEM enriches events before its rules run. `GET /rules` lists the catalogue with each rule's risk assessment.
- **Risk is assessed with [NIST SP 800-30 Rev. 1](https://doi.org/10.6028/NIST.SP.800-30r1)**, *Guide for Conducting Risk Assessments* (`server/scoring/nist.py`). Each rule's `risk` block gives a **likelihood** and an **impact** as semi-quantitative values 0-100 on the NIST scales (Tables G-4 and H-3), with a written rationale. The **level of risk** is read from the NIST likelihood x impact matrix (**Table I-2**).
- **Risk value = likelihood x impact / 100**, the likelihood x consequence form of **ISO/IEC 27005**, kept inside the Table I-3 range of the level Table I-2 gives, so the number and the level never disagree.
- **Levels are NIST's five (Table I-3)**: Very Low 0-4, Low 5-20, Moderate 21-79, High 80-95, Very High 96-100. Each maps to one Sigma level (Very Low = informational, Low = low, Moderate = medium, High = high, Very High = critical); a rule whose Sigma level does not match its NIST level of risk is refused at startup.

| Layer | Finding (Sigma rule file) | Likelihood | Impact | NIST risk (Table I-2) | Value |
| --- | --- | --- | --- | --- | --- |
| rule | `unknown_device` - never seen before | Moderate (30) | High (85) | Moderate | 25.5 |
| rule | `device_type_mismatch` - same identity, different declared type | High (85) | High (90) | High | 80 |
| rule | `serial_reuse_across_models` - serial belongs to a different VID/PID | High (80) | High (85) | High | 80 |
| rule | `descriptor_mismatch` - fingerprint or descriptor fields differ from this device's recorded profile | High (80) | High (85) | High | 80 |
| rule | `descriptor_model_mismatch` - new unit whose fingerprint matches no known unit of the model it claims | High (80) | High (85) | High | 80 |
| rule | `serial_format_mismatch` - new unit's serial format differs from other units of the same model | Moderate (40) | High (85) | Moderate | 34 |
| rule | `missing_serial` - new unit has no serial where other units of the model do | Moderate (35) | High (85) | Moderate | 29.8 |
| rule | `programmable_hid_board` - a BadUSB-capable board (Digispark, Teensy, Flipper Zero, Arduino Leonardo/Micro) presenting a keyboard | High (80) | High (90) | High | 80 |
| rule | `blocklisted_device` - an investigator blocklisted this device | High (90) | Very High (96) | Very High | 96 |
| rule | `same_model_new_serial` - new unit of a model that was on this machine in the last 24 h, under a different serial (lookalike swap) | Low (15) | High (85) | Low | 12.8 |
| rule | `keystroke_injection` - a new keyboard typed at machine speed, including bursts between `DELAY` pauses (typing report) | Very High (96) | Very High (96) | Very High | 96 |
| rule | `large_transfer` - a large copy to USB storage, by size or 10x its usual (at disconnect) | Moderate (60) | Very High (96) | High | 80 |
| rule | `large_transfer_off_hours` - that copy was made before 07:00 or from 21:00 local (adds to `large_transfer`) | Low (20) | Moderate (50) | Low | 10 |
| rule | `new_source_machine` - device never connected to this machine before (filtered out for devices marked trusted) | Low (20) | Moderate (50) | Low | 10 |
| rule | `future_timestamp` - the agent dated the event more than 5 minutes after the server received it (any event type) | Moderate (40) | Moderate (60) | Moderate | 24 |
| ML | `behavioural_outlier` - Isolation Forest or One-Class SVM, explained with SHAP | Low-Moderate (20-79, from the model) | Moderate (60) | Low-Moderate | 12-47 |
| ML | `unseen_behaviour` - a feature far outside anything in the training data | Moderate (50) | Moderate (60) | Moderate | 30 |

Likelihood and impact are still judgements, as they are in any NIST or ISO risk assessment, but each is stated on the standard scale with its rationale in the rule file, where it can be reviewed and changed. `python -m server.scoring.calibrate` checks every likelihood against the precision each rule actually achieves on the labelled scenarios, and the dashboard shows each finding's NIST rating in the risk explanation. Why these standards, the research gap they fill and the references are in [docs/STANDARDS.md](docs/STANDARDS.md).

**MITRE ATT&CK.** Every finding lists its technique, taken from its Sigma rule's `attack.tNNNN` tags (`server/detection/mitre.py`): T1200 Hardware Additions, T1036 Masquerading, T1059 Command and Scripting Interpreter for a "drive" that types, T1091 Replication Through Removable Media for a device spreading across machines, T1052.001 Exfiltration over USB, and T1070.006 Timestomp for a forged event time. Incidents roll these up. Behavioural ML findings are left unmapped, because an unusual pattern alone does not name a technique.

**Attack-board IDs are one weak signal.** VID and PID are firmware strings; tools like the Hak5 Key Croc copy the real keyboard's IDs by default. The structural fingerprint and the behavioural model are what catch a spoofed board.

**Structural fingerprint.** The server hashes the descriptor tree without VID, PID or serial (`server/detection/fingerprint.py`). Those identifiers are firmware strings anyone can set; the interface/endpoint layout follows from what the hardware does. Two genuine units of a model share a fingerprint, so a clone that copies a SanDisk's identity but also exposes a keyboard interface is caught even on its first connection.

**Behavioural features** (per connect, from the device's own history): time since the last connection and its ratio to this device's median gap, hour of day and distance from this device's usual hour, connections in the last hour and day, distinct machines, enumeration time relative to this device's median, and whether the interface enumeration order changed. Isolation Forest picks one random feature per split, so a single extreme feature can leave the overall score near normal; `unseen_behaviour` reports values more than one training-range beyond anything seen in training (or any change in a feature that never varied).

An event's risk is its findings' values added up, capped at 100: NIST SP 800-30 risk aggregation, where several moderate risks that materialise together can make a higher one (Chapter 2, p. 13). NIST describes aggregation but prescribes no formula; the sum is TraceForge's choice. Its level is the Table I-3 level of that total, so an event is never rated below its worst finding. There is no baseline: an event no rule or model flags is 0, Very Low. Every factor is stored with its explanation, and ML findings carry their drivers (e.g. "time since last connection was 181x shorter than this device's historical baseline").

**Incidents and cases.** An incident opens when risk reaches NIST **High** (80+, Table I-3: a severe or catastrophic adverse effect), either from one event or **aggregated over one device's findings within 24 hours**, so Low and Moderate findings that are harmless alone still escalate together. Later events on the same machine join an active incident within 30 minutes if they involve a device already in it or are themselves suspicious; routine Very Low and Low events are never dragged in. A device's risk belongs to the whole attachment: typing reports and the disconnect carry the riskiest event of the same attachment forward (its factors are copied, tagged with the event they came from) and add their own, so a clean typing report cannot reset a suspicious keyboard and an injection found while typing does not vanish at unplug. Incidents on different machines within 24 hours that involve the same device, or a device presenting the same serial number, are grouped into a case. A device that has an open incident and then appears on another machine opens an incident there as well, even if that connection looks normal on its own. The dashboard shows the case and links its incidents. Investigators can set an incident to open / investigating / resolved and attach notes; resolved incidents stop collecting events.

## Device trust

Each device gets a trust score from 0 to 100 from its whole history (`server/scoring/trust.py`). It starts at 50, earns up to +30 for clean connections and up to +10 for time known, and loses half of its highest risk score in its last 30 days of activity plus 15 per unresolved incident. Levels: trusted (70+), suspicious (40-69), untrusted (below 40). A new device starts untrusted and earns trust. Every factor is returned with its reason.

Investigators can override it (`PUT /devices/{id}/trust`, or the buttons on the device profile):
- **Trusted** (allowlist) silences `new_source_machine` for a device that legitimately moves between machines; clone, descriptor and behaviour checks still apply.
- **Blocklisted** sets trust to 0, adds `blocklisted_device` on every connection and keeps the device out of ML training.

Nothing is blocked on the machine: TraceForge is an investigation platform, not a block/allow agent.

## Evidence integrity

Every event stores `record_hash = SHA-256(prev_hash + its canonical evidence)`, so all events form one hash chain (`server/integrity.py`). Editing, deleting or reordering any stored event breaks every hash after it. `GET /integrity/verify`, also shown in the dashboard header, says whether the chain is intact and names the first altered event. Databases created before this feature are chained at startup. Forensic exports carry each event's hash and the chain head, and send `X-Content-SHA256` for the exact file, which the dashboard shows after a download.

## Security mechanisms

Every security mechanism (hash chain, signatures, TLS, spool encryption, key derivation, access control),
what it protects, where it lives, and which Information Security Lab topic it applies is listed in
[docs/SECURITY.md](docs/SECURITY.md), along with what is deliberately not used and why.

## HTTPS (TLS)

Agents send their key and every event to the server, and investigators send passwords and session
tokens. Over plain HTTP anyone on the lab network can read and replay all of it, so for anything beyond
a demo on one machine, serve the API over HTTPS. A lab has no public domain, so TraceForge creates its
own small certificate authority (`server/tls.py`): ECDSA P-256 keys, SHA-256 signatures, a CA limited to
signing server certificates (`pathlen 0`), and a server certificate naming every hostname and IP agents use.
Python's TLS stack only accepts TLS 1.2 and 1.3.

```bash
python -m server.manage tls-init --host 192.168.1.20 --host LAB-SERVER   # certs/ca.crt, server.crt, keys (owner-only)
# .env: TLS_CERT_FILE=certs/server.crt  TLS_KEY_FILE=certs/server.key
python -m server.run                                                       # HTTPS on :8000
```

With Docker: create the certificates as above (or inside the container, see the top of
`docker-compose.tls.yml`), then `docker compose -f docker-compose.yml -f docker-compose.tls.yml up -d --build`.

- **Agents:** `TRACEFORGE_SERVER=https://LAB-SERVER:8000` and `TRACEFORGE_CA_BUNDLE=path/to/ca.crt`. The agent
  trusts that CA for its own requests only, never falls back to an unverified connection (events stay spooled
  and it says why), and warns at startup if it is sending to another machine over plain HTTP.
- **Browsers:** trust `certs/ca.crt` (Windows: `certutil -user -addstore Root certs\ca.crt`).
- Re-running `tls-init` issues a new server certificate from the same CA, so agents keep working. Keep `ca.key`
  private: whoever has it can issue certificates your agents will trust.
- Behind a reverse proxy that already does HTTPS, set `TLS_TERMINATED_BY_PROXY=true` instead.
- The server warns at startup (and in `GET /system/security`) while it serves plain HTTP.

## Signed reports and attestations

A SHA-256 hash proves a file is unchanged, but anyone who edits a report can simply recompute its
hash. Every forensic export is therefore also **digitally signed** by the server (`server/signing.py`):
RSA-2048 with RSA-PSS over SHA-256, the signature scheme with a security proof. The signature covers the
exact bytes downloaded, so it gives integrity, **authenticity** (this TraceForge server produced it) and
**non-repudiation**.

- The key pair is created on first start in `server/model_artifacts/signing_key.pem` (owner-only file;
  the Docker model volume keeps it across restarts) and logged in the audit log with its key id.
  Set `SIGNING_KEY_PASSPHRASE` to store the private key encrypted (PKCS#8 PBES2: PBKDF2-HMAC-SHA256
  derives an AES-256 key, AES-256-CBC encrypts the key file).
- `GET /signing/public-key` publishes the public key without a login, because verifiers (a court,
  another lab) usually have no account.
- The dashboard **verifies each export's signature in the browser** (WebCrypto) as soon as it downloads,
  shows "Signature valid" with the key id, and offers **Save .sig** and **Public key** to keep with the file.
- `GET /integrity/attestation` returns a signed statement of the evidence chain (head hash, event count,
  intact or not, time). Keeping one in the case file means even deleting the newest events, which the
  hash chain alone cannot reveal, is caught later.
- Anyone can check a report offline with only the `cryptography` package:

```bash
python tools/verify_signature.py report.json report.json.sig --public-key traceforge_public.pem
python tools/verify_signature.py --attestation attestation.json --public-key traceforge_public.pem
```

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

When a new device presents a keyboard, the agent records **when** its keys go down and reports only timing statistics (count, rate, gaps, regularity, share of sub-20 ms gaps); key codes are never read, and mouse buttons are not counted. The watch starts the moment the HID interface appears (not after the connect has been sent, which takes longer than an injector waits) and lasts `TRACEFORGE_TYPING_WATCH_S` seconds (default 30). People type with roughly 80-250 ms between keys and a lot of variation; `keystroke_injection` fires for 15+ keys with any of:

- a sustained rate of 25+ keys/s,
- a median gap under 30 ms with almost no variation,
- 15+ gaps under 20 ms making up at least half the typing. This one catches Rubber Ducky scripts that pause between bursts with `DELAY`, which drags the overall rate down and the variation up so the first two miss them.

**How far must an attacker go to evade this?** `python -m server.evasion` plays slow-down, chunking
and wait-out-the-window strategies against the real agent summary and Sigma rule: chunked `DELAY` payloads
are always caught, but typing just under 25 keys/s (13.4 s for a 300-key payload, 10x slower) or waiting
30 s after plug-in evades. Results, two measured countermeasures and why connect-time rules still catch the
device are in [docs/EVASION.md](docs/EVASION.md).

Backends: python-evdev on Linux (the agent needs the `input` group), the Raw Input API on Windows. Set `TRACEFORGE_WATCH_TYPING=0` on the agent to turn it off.

## Data exfiltration watch

While a storage device is attached, the agent samples (every `TRACEFORGE_SAMPLE_S`, default 2 s) the OS's per-disk I/O counters (`/sys/block/*/stat`, WMI disk counters) and sends the bytes written and read with the disconnect; no file names or contents are read. `large_transfer` (T1052.001 Exfiltration over USB) fires for a copy of `EXFIL_THRESHOLD_MB` (default 500) or 10x the device's usual, scoring higher outside working hours.

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
| `AGENT_KEYS` | none | per-machine keys, `HOST=sha256,...`; each is accepted only for events naming that host (`python -m server.manage agent-key HOST`) |
| `REQUIRE_AGENT_KEYS` | `false` | refuse the shared key on `/events/ingest` once every agent has its own |
| `AUTH_ENABLED` | `false` | investigator logins and roles |
| `LOGIN_MAX_FAILURES`, `LOGIN_WINDOW_MINUTES` | `5`, `15` | failed logins per username and per client address before `/auth/login` answers 429 |
| `POSTGRES_PASSWORD` | `traceforge` | database password for docker-compose |
| `TLS_CERT_FILE`, `TLS_KEY_FILE` | none | serve HTTPS with these (from `tls-init`); `python -m server.run` and the Docker image use them |
| `TLS_TERMINATED_BY_PROXY` | `false` | a reverse proxy handles HTTPS in front of the server |
| `TRACEFORGE_CA_BUNDLE` (agent) | none | the TraceForge `ca.crt`, so the agent trusts the server's certificate |
| `SIGNING_KEY_PATH`, `SIGNING_KEY_PASSPHRASE` | `server/model_artifacts/signing_key.pem`, none | where the signing key lives; passphrase to store it encrypted |
| `CORS_ORIGINS` | `http://localhost:5173,http://127.0.0.1:5173` | browser origins allowed to call the API |
| `ML_ALGORITHM` | `iforest` | `iforest` or `ocsvm` |
| `RETRAIN_INTERVAL_HOURS` | `0` | scheduled retraining |
| `TIMEZONE` | `Asia/Kolkata` | what "night" means, and the zone the dashboard shows |
| `EXFIL_THRESHOLD_MB` | `500` | a copy this large to USB storage is flagged |
| `TRACEFORGE_TYPING_WATCH_S`, `TRACEFORGE_SAMPLE_S` (agent) | `30`, `2` | keystroke watch window; storage counter sampling interval |
| `MODEL_PATH` | `server/model_artifacts/iforest.joblib` | where the trained model is saved; use a separate file for real data |

The server logs a `SECURITY:` warning at startup for every setting still at its development default
(no logins, no or placeholder keys, shared agent key, default database password); `GET /system/security` lists them.

## Training on real data

Keep real data in its own database and model so the demo stays intact. In one PowerShell window:

```powershell
$env:DATABASE_URL = "sqlite:///traceforge-real.db"
$env:MODEL_PATH = "server/model_artifacts/real.joblib"
.venv\Scripts\python -m server.manage import real-data\setupapi.dev.log --machine $env:COMPUTERNAME --registry real-data\usb.reg
.venv\Scripts\uvicorn server.main:app   # keep it and the agent running for 1-2 weeks of normal use
.venv\Scripts\python -m server.manage train
```

The model needs at least 30 connections. setupapi records only each device's first install, so most training rows come from the agent watching normal use. Connections that became part of an incident, and blocklisted devices, are left out of training. Keep `real-data\` out of git: it holds your device serials.

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

## Measuring the whole pipeline

```bash
python -m server.evaluate                       # detection per scenario: rules vs ML vs both, and incidents
python -m server.scoring.calibrate              # each Sigma rule's measured precision vs its NIST likelihood
```

`server/evaluate.py` trains on four weeks of synthetic normal use, holds out two weeks to measure false
alarms, and replays 8 randomised trials of each attack and of three benign look-alikes through the live
pipeline. What reaches an investigator is an **incident**: NIST High (80+), from one event or from a
device's findings aggregated over 24 hours. Default seed:

| Scenario | Opens an incident | One event at NIST High: hybrid | rules only | ML only |
| --- | --- | --- | --- | --- |
| type_switch (storage stick turns into a keyboard) | 100% | 100% | 100% | 0% |
| serial_clone | 100% | 100% | 100% | 0% |
| burst (rapid reconnects, no rule fires) | 100% | 25% | 25% | 0% |
| missing_serial | **0%** | 0% | 0% | 0% |
| descriptor_swap | 100% | 100% | 100% | 0% |
| keystroke_injection | 100% | 100% | 100% | 0% |
| ducky_with_delays (bursts separated by DELAY) | 100% | 100% | 100% | 0% |
| night_exfiltration (1-6 GB copied at night) | 100% | 100% | 100% | 0% |
| *benign:* new unknown device | 0% | 0% | 0% | 0% |
| *benign:* person typing on a known keyboard | 0% | 0% | 0% | 0% |
| *benign:* 20-400 MB daytime copy | 0% | 0% | 0% | 0% |
| held-out normal use (false alarm rate) | 0% | 0% | 0% | 0% |

Seeds 1-3 give the same incident results. The behavioural burst is the case for aggregation: no single
connection reaches High, but a run of Moderate model findings within minutes does. A serial-less clone of a known
model (`missing_serial`, Moderate) plus `unknown_device` (Moderate) sums to about 55, so it is shown as
Moderate risk but opens no incident: its likelihood is rated Moderate because a missing serial can also be a
read error, and it was deliberately not raised just to pass this scenario. At NIST Moderate (21+) per event,
the model alone also flags every daytime copy and 8% of normal use, which is why incidents start at High.

For comparison, USBeSafe (RAID 2019) reports 95.7% detection at 0.21% false positives on real USB traffic;
TraceForge's numbers are on synthetic data and are not directly comparable.

## API

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/events/ingest` | agent pushes a USB event (`X-API-Key`: the shared key or that machine's agent key) |
| GET | `/devices?q=&risk_level=&known=&trust_level=`, `/devices/{id}` | profiles with latest risk and trust, search and filtering |
| PUT | `/devices/{id}/trust` | set `auto`, `trusted` or `blocklisted`, with an optional note (investigator) |
| GET | `/devices/{id}/timeline` | chronological events with anomalies |
| GET | `/devices/{id}/export?format=json\|csv` | export complete forensic investigation dossier (JSON/CSV) |
| GET | `/anomalies?device_id=&source=` | flagged anomalies with explanations |
| GET | `/risk-scores/{device_id}` | score history with reasoning |
| GET | `/incidents`, `/incidents/{id}` | correlated incidents, with their cross-machine case |
| PATCH | `/incidents/{id}` | set status (`open`, `investigating`, `resolved`) and/or note (investigator) |
| GET | `/integrity/verify` | check the evidence hash chain |
| GET | `/integrity/attestation` | signed statement of the chain head, for the case file |
| GET | `/signing/public-key` | the server's RSA public key for verifying signatures (no login needed) |
| GET | `/stats`, `/ml/status` | dashboard counters, model state |
| POST | `/ml/train` | retrain the model on stored history (admin login or `X-API-Key`) |
| GET, POST | `/auth/config`, `/auth/login`, `/auth/logout`, `/auth/me`, `/auth/users` | logins and user management |
| GET | `/audit?actor=&action=` | audit log (admin) |
| GET | `/graph?days=`, `/graph?incident_id=` | attack graph, or one case's events for replay |
| GET | `/incidents/{id}/story` | plain-English account with next steps |
| POST, GET | `/evidence/import`, `/evidence/imports` | import seized-machine USB history (investigator); the import record |
| GET | `/ml/drift?days=` | model health and drift per feature |
| GET | `/rules` | the Sigma rule catalogue, each rule's NIST SP 800-30 likelihood, impact and level of risk, and the Table I-2 matrix |
| GET | `/system/security` | which security settings are still at development defaults |

Run the tests with `python -m pytest`.

## Known limits

- HTTPS is opt-in (`tls-init`): the default setup serves plain HTTP, which is only safe on one machine.
- Agents authenticate with keys, not client certificates (mutual TLS): uvicorn does not pass the client certificate to the application, so it could not be tied to a machine the way agent keys are.
- With only the shared `API_KEY`, any agent can report as any machine. Give each machine its own key (`AGENT_KEYS`) and set `REQUIRE_AGENT_KEYS=true`; then one machine's key can be revoked by removing its line.
- The evidence chain proves events were not changed after they arrived, not that they were true when they arrived. The server records when each event was received and who sent it (`received_at`, `reported_by`) and flags events dated in the future; a late date is normal, because the agent spools events while the server is down.
- The keystroke watch covers the first `TRACEFORGE_TYPING_WATCH_S` seconds after plug-in. A payload that waits longer before typing is not timed; raise the window if that matters. On Windows, two keyboards plugged in within the same window share one Raw Input registration, so only the later one is timed.
- Transfer metering reads disk counters every `TRACEFORGE_SAMPLE_S` seconds and they vanish at unplug, so the last interval is not counted, and on Linux writes still in the page cache are counted only once flushed. Treat byte counts as a lower bound.
- Rule likelihoods are analyst judgements on the NIST scale. `server.scoring.calibrate` measures each rule's precision on the synthetic scenarios, where every rule is more precise than its likelihood; real environments have more benign look-alikes, so the ratings are not raised to match.
- Failed-login throttling is kept in memory per server process (fine for the single-process deployment here).
- Ingestion chains one event at a time under an in-process lock, so run a single server process.
- The evidence chain detects edits, deletions and reordering. Removing only the newest events is caught by comparing against a chain head noted earlier (every forensic report prints it).
- The ML model has only been trained and measured on simulated data here. Retrain on real history before trusting its thresholds.
- Windows WMI events are checked by the WMI service about once a second, so a connect can be reported up to ~1 s late (Linux udev events are immediate).
- On Windows, interface nodes do not name their parent, so they are matched to the new device by VID/PID during the settle window.
- If libusb cannot open the device list (no backend), the agent still reports the event, with the OS fields only and no fingerprint; the dashboard says so.
- Trust on first use: a device that is anomalous the first time but keeps reconnecting becomes "known" afterwards. In the evaluation this is the only miss (a repeated serial-less clone).
