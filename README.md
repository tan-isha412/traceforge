# TraceForge

USB forensic investigation and device trust analysis. A live agent on each monitored machine reports USB connect/disconnect events to a central server, which profiles devices, detects identity anomalies (rules + explainable ML), scores risk, and groups related suspicious events into incidents. A React dashboard shows it all.

```
<<<<<<< Updated upstream
agent (Windows WMI events / Linux udev, libusb descriptors)
   --POST /events/ingest (X-API-Key)--> FastAPI --> PostgreSQL
                                          |-- fingerprint.py  structural fingerprint of the descriptor tree
                                          |-- rules.py        identity / descriptor / source-machine checks
                                          |-- ml_model.py     Isolation Forest + SHAP, out-of-range check
                                          |-- risk.py         weighted score with recorded reasoning
                                          '-- correlate.py    incidents per machine, cases across machines
React dashboard <-- REST JSON (devices, descriptor profiles, timelines, incidents, cases)
=======
agent (Windows, WMI) --POST /events/ingest--> FastAPI --> PostgreSQL
                                                |-- rules.py        identity / descriptor / source-machine checks
                                                |-- ml_model.py     Isolation Forest + SHAP explanations
                                                |-- risk.py         weighted score with recorded reasoning
                                                '-- correlate.py    incidents (device or machine, 30 min window, across machines)
React dashboard <-- REST JSON (devices, timelines, incidents, anomalies)
>>>>>>> Stashed changes
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

The seeder replays six weeks of normal usage, trains the ML model on it, then runs eight planted attack scenarios through the live pipeline: type-switching BadUSB device, serial cloning, behavioural burst, missing serial, plain unknown device, cross-machine spread, a model clone whose descriptor adds a keyboard interface, and enumeration drift.

## Live agent

Run on each monitored machine (Windows or Linux; other systems fall back to libusb polling):

```bash
set TRACEFORGE_SERVER=http://<server>:8000
set TRACEFORGE_API_KEY=<same as the server's API_KEY>
.venv\Scripts\python agent\agent.py
```

<<<<<<< Updated upstream
- **Events, not polling:** WMI instance creation/deletion events on Windows, the udev netlink socket on Linux.
- **Enumeration:** after a device appears the agent waits 1.5 s, recording which interfaces appear, in what order and how long enumeration took.
- **Real descriptors:** it then reads the device and configuration descriptors through libusb (`pyusb` + `libusb-package`, no driver changes needed): USB version, device class, every interface (class/subclass/protocol) and every endpoint (direction, transfer type, packet size).
- **Offline queue:** events carry the time the OS reported them. If the server is unreachable they are kept in `~/.traceforge/spool.jsonl` and retried every 10 s, in order, across restarts.
- On Linux, reading descriptors works as a normal user; seeing events needs no extra permissions.
=======
Plug in a USB device and it appears in the dashboard within a few seconds. For each device the agent reads the real USB interface classes (audio, HID, video, storage, ...) from Windows' compatible IDs, so descriptor structure is fingerprinted, not just VID/PID/serial. If the server is unreachable, events are queued in `agent/pending_events.jsonl` with their original timestamps and delivered in order once it is back.

**Tests**

```bash
.venv\Scripts\python -m pytest
```
>>>>>>> Stashed changes

**Detection quality** (about 2 minutes; uses an in-memory database and a temporary model, so your data is untouched)

```bash
.venv\Scripts\python -m server.evaluate --show-misses
```

Trains on four weeks of synthetic normal usage, measures false alarms on two held-out weeks, runs randomised labelled attack trials, and compares hybrid vs rules-only vs ML-only plus Isolation Forest vs One-Class SVM.

**Timezone**: everything is stored in UTC. `TIMEZONE` in `.env` (default `Asia/Kolkata`) defines "night" for the ML hour-of-day feature and the seeder; the dashboard shows times in the same zone (`VITE_TIMEZONE` to change it).

**Schema changes**: tables are created at startup but never altered. After pulling a version that adds columns, re-run `python -m server.seed_synthetic_data --reset`.

## How detection works

| Layer | Finding | Weight |
| --- | --- | --- |
| rule | `unknown_device` - never seen before | 25 |
| rule | `device_type_mismatch` - same identity, different declared type | 40 |
| rule | `serial_reuse_across_models` - serial belongs to a different VID/PID | 40 |
| rule | `descriptor_mismatch` - fingerprint or descriptor fields differ from this device's recorded profile | 35 |
| rule | `descriptor_model_mismatch` - new unit whose fingerprint matches no known unit of the model it claims | 35 |
| rule | `missing_serial` / `serial_format_mismatch` - differs from other units of the same model | 30 |
| rule | `new_source_machine` - device never connected to this machine before | 15 |
| ML | `behavioural_outlier` - Isolation Forest, explained with SHAP | 15-45 |
| ML | `unseen_behaviour` - a feature far outside anything in the training data | 30 |

<<<<<<< Updated upstream
**Structural fingerprint.** The server hashes the descriptor tree without VID, PID or serial (`server/detection/fingerprint.py`). Those identifiers are firmware strings anyone can set; the interface/endpoint layout follows from what the hardware does. Two genuine units of a model share a fingerprint, so a clone that copies a SanDisk's identity but also exposes a keyboard interface is caught even on its first connection.

**Behavioural features** (per connect, from the device's own history): time since the last connection and its ratio to this device's median gap, hour of day and distance from this device's usual hour, connections in the last hour and day, distinct machines, enumeration time relative to this device's median, and whether the interface enumeration order changed. Isolation Forest picks one random feature per split, so a single extreme feature can leave the overall score near normal; `unseen_behaviour` reports values more than one training-range beyond anything seen in training (or any change in a feature that never varied).

Score = 5 baseline + sum of weights, capped at 100. Levels: low < 25 <= medium < 50 <= high < 75 <= critical. Every factor is stored with its explanation, and ML findings carry their drivers (e.g. "time since last connection was 181x shorter than this device's historical baseline").

**Incidents and cases.** A connection scoring 40+ opens an incident; later events for the same device and machine within 30 minutes join it. Incidents on different machines within 24 hours that involve the same device, or a device presenting the same serial number, are grouped into a case. A device that has an open incident and then appears on another machine opens an incident there as well, even if that connection looks normal on its own. The dashboard shows the case and links its incidents.

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
=======
Score = 5 baseline + sum of weights, capped at 100. Levels: low < 25 <= medium < 50 <= high < 75 <= critical. Every factor is stored with its explanation, and ML findings carry the SHAP drivers (e.g. "inter-event timing was 20s vs a typical 69,836s"). A connection scoring 40+ opens an incident. Later events join an active incident within 30 minutes if they involve a device already in it (even on a different machine) or are themselves suspicious and on a machine already in it; routine low-risk events are never dragged in. Disconnects inherit the score of the connection they close. Investigators can set an incident to open / investigating / resolved and attach notes; resolved incidents stop collecting events.
>>>>>>> Stashed changes

## API

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/events/ingest` | agent pushes a USB event (needs `X-API-Key` when `API_KEY` is set) |
| GET | `/devices`, `/devices/{id}` | profiles with latest risk |
| GET | `/devices/{id}/timeline` | chronological events with anomalies |
| GET | `/anomalies?device_id=&source=` | flagged anomalies with explanations |
| GET | `/risk-scores/{device_id}` | score history with reasoning |
<<<<<<< Updated upstream
| GET | `/incidents`, `/incidents/{id}` | correlated incidents, with their cross-machine case |
=======
| GET | `/incidents`, `/incidents/{id}` | correlated incidents (machines, devices, timeline) |
| PATCH | `/incidents/{id}` | set status (`open`, `investigating`, `resolved`) and/or note |
>>>>>>> Stashed changes
| GET | `/stats`, `/ml/status` | dashboard counters, model state |
| POST | `/ml/train` | retrain the model on stored history (needs `X-API-Key`) |

Run the tests with `python -m pytest`.

## Known limits

<<<<<<< Updated upstream
- The dashboard and read endpoints have no login; only writes are protected by the API key. Intended for a lab network.
- The ML model has only been trained and measured on simulated data here. Retrain on real history before trusting its thresholds.
- Windows WMI events are checked by the WMI service about once a second, so a connect can be reported up to ~1 s late (Linux udev events are immediate).
- On Windows, interface nodes do not name their parent, so they are matched to the new device by VID/PID during the settle window.
- If libusb cannot open the device list (no backend), the agent still reports the event, with the OS fields only and no fingerprint; the dashboard says so.
=======
- The agent polls WMI every 2 s (no kernel-level hooks), so a plug-in shorter than that can be missed, and it runs on Windows only.
- Live devices report `pnp_class`, `service` and `interface_classes`. `endpoint_count` exists only in the synthetic dataset (reading endpoints needs a libusb-level library).
- Trust on first use: a device that is anomalous the first time but keeps reconnecting becomes "known" afterwards. In the evaluation this is the only miss (a repeated serial-less clone).
- No authentication on the API; intended for a lab network.
- The ML model is trained on whatever history exists; retrain with `POST /ml/train` once real data accumulates.
>>>>>>> Stashed changes
