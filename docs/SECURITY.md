# Security mechanisms in TraceForge

A forensic tool is only worth as much as the evidence it keeps. This page lists every security
mechanism TraceForge uses, what it protects, where it lives in the code, and which part of the
Information Security Lab syllabus (Labs 1-8) it applies. The last sections cover what is
deliberately not used, and why.

## What needs protecting

| Asset | Threat | Property needed |
| --- | --- | --- |
| USB events from agents | forged events, a sniffed agent key, a fake server collecting events | authenticity, confidentiality in transit |
| Events queued on a monitored PC | read or edited before they reach the server | confidentiality, integrity |
| The stored evidence log | edited, deleted or reordered after the fact | integrity |
| Reports handed to others | altered, or passed off as TraceForge output | integrity, authenticity, non-repudiation |
| Investigator accounts | password guessing, stolen passwords or tokens | authentication, access control |

## Mechanisms, by lab

### Lab 2: Symmetric encryption (AES, modes of operation)

| Mechanism | Where | Protects |
| --- | --- | --- |
| **AES-256-GCM** on every line of the agent's offline spool, random 96-bit nonce per line | `agent/spool.py` | Events waiting on a monitored PC: unreadable without the agent's key, and any edit fails the 128-bit GCM tag, so the line is quarantined and never sent |
| **AES-256-CBC** encrypting the server's signing key file when `SIGNING_KEY_PASSPHRASE` is set (PKCS#8 PBES2) | `server/signing.py` | A stolen key file is useless without the passphrase |
| **TLS 1.2/1.3** bulk encryption: measured against the server, TLS 1.3 negotiates `TLS_AES_256_GCM_SHA384` and TLS 1.2 `ECDHE-ECDSA-AES256-GCM-SHA384`; TLS 1.1 and older are refused | `server/run.py` | Everything between agents, browsers and the server |

GCM rather than the CBC/CTR modes from Lab 2: it is authenticated encryption, so integrity comes with
confidentiality in one step, and a tampered spool line cannot decrypt to something plausible.

### Lab 3: Asymmetric cryptography (RSA, ECC)

| Mechanism | Where | Protects |
| --- | --- | --- |
| **RSA-2048** key pair, public exponent 65537 | `server/signing.py` | Signs exports and attestations (Lab 6) |
| **ECDSA on P-256 (secp256r1)** for the TLS certificate authority and server certificate | `server/tls.py` | Proves to agents and browsers that they reach the real server |
| **ECDHE** key exchange in the TLS handshake (Diffie-Hellman over elliptic curves) | Python `ssl` / OpenSSL | Fresh session keys per connection, so a later key leak does not expose past traffic (forward secrecy) |

ECC for the certificates because it gives 128-bit security with 256-bit keys, far smaller and faster than
RSA-3072; RSA for signatures because it is what Lab 6 uses and every verifier supports it.

### Lab 4: Key management and access control

| Lab 4 concept | TraceForge |
| --- | --- |
| **KDF**: DK = KDF(Key, Salt, Iterations) | Passwords: **PBKDF2-HMAC-SHA256**, 16-byte random salt, 600,000 iterations (`server/auth.py`). Signing-key encryption: PBKDF2 inside PBES2. Spool key: **HKDF-SHA256** from the agent key and hostname (`agent/spool.py`) |
| **Key generation / entropy** | All keys and tokens from the OS CSPRNG (`secrets`, `os.urandom`): 256-bit agent keys and session tokens |
| **Key expiry**: Expiry = t0 + L | Sessions expire after 12 h; server certificates after 397 days; the CA after 5 years |
| **Key rotation and revocation** | Per-agent keys (`AGENT_KEYS`) are revoked one machine at a time; `tls-init` re-issues the server certificate from the same CA; the signature key id tells verifiers which key signed what |
| **Key storage** | Secrets stored only as SHA-256 hashes (agent keys, API key, session tokens); private keys written owner-only (0600) |
| **Diffie-Hellman** | ECDHE in every TLS handshake (above) |
| **RBAC**: Access(User, Object) = ∃Role : HasRole ∧ CanAccess | Roles `investigator` and `admin` (`server/auth.py`, `require_role`): reading needs a login, changing incidents or trust needs investigator, retraining, users and the audit log need admin |
| **ABAC-style binding** | An agent key is accepted only for events naming its own machine (`server/security.py`) |

### Lab 5: Hashing (SHA-256) for integrity

| Mechanism | Where | Protects |
| --- | --- | --- |
| **Hash chain**: record_hash = SHA-256(prev_hash + event) | `server/integrity.py` | Any edit, deletion or reordering of stored events breaks every later hash; `GET /integrity/verify` finds the first broken event |
| **SHA-256 of each imported evidence file** | `server/forensics/importer.py` | Chain of custody for logs from seized machines; the same file cannot be imported twice |
| **X-Content-SHA256** on every export | `server/routers/devices.py` | The Lab 5 exercise of sending a hash alongside data so the receiver can check it, over HTTP |
| **Structural fingerprint** = SHA-256 of the descriptor tree | `server/detection/fingerprint.py` | Detects a device whose hardware layout differs from what it claims to be |

### Lab 6: Digital signatures

| Mechanism | Where | Protects |
| --- | --- | --- |
| **RSA-PSS with SHA-256** over the exact bytes of every forensic export | `server/signing.py`, `server/routers/devices.py` | Authenticity and non-repudiation: a hash can be recomputed by whoever edits a report; a signature cannot be made without the server's private key |
| **Signed attestation** of the evidence chain head | `GET /integrity/attestation` | Proves the state of the whole log at a moment, so even removing the newest events (which the chain alone cannot show) is caught |
| **Verification in the browser** (WebCrypto) and **offline** | `frontend/src/api.js`, `tools/verify_signature.py` | Anyone with the public key can check a report, with or without TraceForge |

Together with the hash chain this gives the CIA triad the Lab 6 extra exercise asks for: confidentiality
(TLS, spool encryption), integrity (SHA-256 chain, GCM, signatures) and availability of the evidence
(agents spool events while the server is down, and nothing is lost in transit).

### Lab 8: Intrusion detection (the Snort exercise)

TraceForge is a host-based intrusion detection system for USB, built on the same two ideas as Snort:
**signature rules** (`server/detection/sigma_rules/*.yml`: known-bad patterns such as a storage stick that starts
typing, or a programmable attack board) and **anomaly detection** (`server/detection/ml_model.py`:
Isolation Forest over each device's behaviour). Snort inspects network packets; TraceForge inspects USB
devices and what they do. Its rules are written in Sigma, the open format SIEMs use for the same purpose, and
risk is assessed with NIST SP 800-30 (see [STANDARDS.md](STANDARDS.md)).

## Other defences

- **Constant-time comparison** (`hmac.compare_digest`) for every key and password check, against timing attacks.
- **Equal-time login**: an unknown username still costs one full PBKDF2 hash, so response time does not reveal which accounts exist.
- **Failed-login throttling**: 429 after 5 failures per username or per client address in 15 minutes.
- **Audit log** of logins (including failures), incident and trust changes, retraining, imports and signing-key creation.
- **Data minimisation**: the agent never reads file names, file contents or which keys were pressed. Only device identities, timings and byte counts. Less collected means less to leak.
- **Safe defaults reporting**: the server logs a `SECURITY:` warning, and `GET /system/security` lists every setting still at a development default (no logins, no keys, plain HTTP, default database password).

## Deliberately not used

| Syllabus topic | Why not here |
| --- | --- |
| Classical ciphers (Lab 1), DES and 3DES (Lab 2) | Broken or obsolete; AES-GCM replaces them |
| ElGamal, Rabin encryption (Labs 3-4) | Nothing needs public-key *encryption*: TLS handles key exchange, and RSA/ECDSA cover signatures |
| Homomorphic encryption (Lab 7) | No third party computes on TraceForge data without seeing it |
| Searchable encryption (Lab 8) | The server must search and analyse events in the clear to detect attacks; the database is protected by access control and disk encryption instead |
| Encrypting the database inside the app | It would break searching, filtering and the ML features. Encrypt the server's disk instead (BitLocker, LUKS); the stored data is low-sensitivity by design (see data minimisation) |
| Mutual TLS for agents | uvicorn does not pass the client certificate to the application, so it could not be tied to a machine; per-agent keys over TLS do that |

## Limits

- HTTPS is opt-in (`python -m server.manage tls-init`); the default setup serves plain HTTP, which is only safe on a single machine.
- The signing key and the CA key sit on the server. Whoever controls the server can sign; a hardware security module would remove that, and is out of scope for this project.
- The evidence chain proves events were not changed after they arrived, not that they were true when they arrived. Per-agent keys, TLS and the future-timestamp check narrow that gap.
