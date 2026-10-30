# How TraceForge detects and scores USB risk, and which standards it rests on

There is no published standard that scores the risk of an individual USB device. Risk methods
(NIST SP 800-30, ISO/IEC 27005, OWASP, FAIR) rate risks in general, CVSS scores vulnerabilities,
NIST SP 800-53 says which media to restrict, MITRE ATT&CK names attack techniques without scoring
them, and published USB detectors (USBeSafe, GoodUSB, USB-Watch) each use their own internal scoring.
TraceForge fills the gap by building on standards that each cover one part of the problem:

| Question | Answered by |
| --- | --- |
| How are detections written? | **Sigma**, the open, vendor-neutral detection rule format used across SIEMs (`server/detection/sigma_rules/*.yml`, run by `server/detection/sigma.py`) |
| How risky is what a rule found? | **NIST SP 800-30 Rev. 1**: likelihood and impact on the 0-100 semi-quantitative scales (Tables G-4, H-3), level of risk from the Table I-2 matrix (`server/scoring/nist.py`) |
| What number does a finding add? | likelihood x impact / 100, the likelihood x consequence form of **ISO/IEC 27005**, kept inside the Table I-3 range of its level |
| Which attack is it? | **MITRE ATT&CK** tags in each Sigma rule |
| Why does a rule exist at all? | NIST SP 800-53 MP-7, GoodUSB, the USB attack taxonomies (references below) |
| Are the likelihoods reasonable? | Each rule's measured precision on labelled scenarios (`server/scoring/calibrate.py`) |
| How good is the detector? | `server/evaluate.py`, compared with published detectors (USBeSafe) |

## What is new here

Sigma rules normally run over log events, and the Sigma rules that already exist for USB only report
that a device was plugged in, from Windows event logs. TraceForge writes Sigma rules over what a USB
device *is* and *does*: its descriptor structure, its serial against other units of its model,
its keystroke timing and the bytes copied to it, under its own log source (`product: traceforge`).
Each rule carries a NIST SP 800-30 risk assessment with a written rationale, and each likelihood is then
checked empirically against labelled attack scenarios. Together:

1. USB-specific Sigma rules over device and behaviour telemetry,
2. a NIST SP 800-30 risk assessment per rule, aggregated per device,
3. likelihoods checked against measured precision.

## The formula

```
finding value = likelihood x impact / 100, within the Table I-3 range of its Table I-2 level
event risk    = sum of its finding values, capped at 100           (NIST risk aggregation, Ch. 2)
level         = Table I-3: Very Low 0-4, Low 5-20, Moderate 21-79, High 80-95, Very High 96-100
incident      = NIST High (80+), from one event or from a device's findings summed over 24 hours
```

A rule's Sigma level must equal its NIST level of risk (Very Low = informational, Low = low,
Moderate = medium, High = high, Very High = critical); the engine refuses a rule where they disagree.
NIST discusses risk aggregation but prescribes no formula: the sum, the cap and the 24-hour window are
TraceForge's design choices, stated as such.

A device's risk belongs to the whole attachment: a typing report or disconnect carries forward the riskiest
event since the device was plugged in and adds its own findings, so a clean typing report cannot reset a
suspicious keyboard, and an injection found while typing survives the unplug.

## The rules

| Rule | Sigma level | Likelihood | Impact | NIST risk (Table I-2) | Value | ATT&CK |
| --- | --- | --- | --- | --- | --- | --- |
| `blocklisted_device` | critical | High (90) | Very High (96) | Very High | 96 | T1200 |
| `keystroke_injection` | critical | Very High (96) | Very High (96) | Very High | 96 | T1200, T1059 |
| `descriptor_mismatch` | high | High (80) | High (85) | High | 80 | T1200, T1036 |
| `descriptor_model_mismatch` | high | High (80) | High (85) | High | 80 | T1200, T1036 |
| `device_type_mismatch` | high | High (85) | High (90) | High | 80 | T1200, T1036, T1059 |
| `large_transfer` | high | Moderate (60) | Very High (96) | High | 80 | T1052.001 |
| `programmable_hid_board` | high | High (80) | High (90) | High | 80 | T1200, T1059 |
| `serial_reuse_across_models` | high | High (80) | High (85) | High | 80 | T1200, T1036 |
| `serial_format_mismatch` | medium | Moderate (40) | High (85) | Moderate | 34 | T1200, T1036 |
| `missing_serial` | medium | Moderate (35) | High (85) | Moderate | 29.8 | T1200 |
| `unknown_device` | medium | Moderate (30) | High (85) | Moderate | 25.5 | T1200 |
| `future_timestamp` | medium | Moderate (40) | Moderate (60) | Moderate | 24 | T1070.006 |
| `same_model_new_serial` | low | Low (15) | High (85) | Low | 12.8 | T1200, T1036 |
| `large_transfer_off_hours` | low | Low (20) | Moderate (50) | Low | 10 | T1052.001 |
| `new_source_machine` | low | Low (20) | Moderate (50) | Low | 10 | T1091 |

The rationale for every likelihood and impact is in the rule's `risk` block; `GET /rules` returns the
catalogue with the NIST scales and matrix. The model's findings are assessed on the same scales: impact
Moderate (60), likelihood from Low to Moderate by how far past the model's threshold a connection is.

## Checking the likelihoods against data

```bash
python -m server.scoring.calibrate --seeds 1 2 3
```

This replays the labelled scenarios of `server/evaluate.py` and reports each rule's precision,
P(attack | rule fired), with a Laplace estimate, next to its NIST likelihood, plus the log-odds from an
L2 logistic regression over all findings:

| Rule | Fired | Measured precision | NIST likelihood |
| --- | --- | --- | --- |
| `keystroke_injection` | 48 | 0.98 | 96 |
| `serial_reuse_across_models` | 118 | 0.99 | 80 |
| `descriptor_mismatch` | 48 | 0.98 | 80 |
| `device_type_mismatch` | 24 | 0.96 | 85 |
| `large_transfer` | 24 | 0.96 | 60 |
| `missing_serial` | 17 | 0.95 | 35 |
| `new_source_machine` | 14 | 0.88 | 20 |
| `unknown_device` | 65 | 0.63 | 30 |

The ordering agrees at both ends: `keystroke_injection` has the highest likelihood and near-perfect
precision, and `unknown_device` the lowest of both. Every measured precision is above its likelihood.
That is expected, and it is why no rating was raised to match: the synthetic data has only three kinds of
benign look-alike (a new keyboard, a person typing, a daytime copy), while a real organisation has many
more (firmware updates, docking stations, macro keyboards, backup jobs), so synthetic precision is an upper
bound. `missing_serial` is the clearest case: its precision here is 0.95, but a missing serial can also be a
read error on real hardware, so it stays Moderate, and a serial-less clone alone opens no incident.

## References

- SigmaHQ, *Sigma Rules Specification*. https://github.com/SigmaHQ/sigma-specification
- NIST SP 800-30 Rev. 1, *Guide for Conducting Risk Assessments* (2012), Appendices G-I. https://doi.org/10.6028/NIST.SP.800-30r1
- ISO/IEC 27005, *Information security risk management* (risk as likelihood x consequence).
- NIST SP 800-53 Rev. 5, control MP-7 *Media Use* (no portable storage without an identifiable owner): the
  control behind `unknown_device`. https://csf.tools/reference/nist-sp-800-53/r5/mp/mp-7/
- MITRE ATT&CK: T1200 Hardware Additions, T1036 Masquerading, T1059 Command and Scripting Interpreter,
  T1091 Replication Through Removable Media, T1052.001 Exfiltration over USB, T1070.006 Timestomp. https://attack.mitre.org
- D. J. Tian, N. Scaife, D. Kumar, M. Bailey, A. Bates, K. R. B. Butler, *SoK: "Plug & Pray" Today -
  Understanding USB Insecurity in Versions 1 through C*, IEEE S&P 2018. Finds that USB attacks exploit
  trust-by-default and that multi-layer defences work best, which is TraceForge's rules + ML + trust design.
- N. Nissim, R. Yahalom, Y. Elovici, *USB-based attacks*, Computers & Security 70 (2017) 675-688.
  Taxonomy of 29 USB attacks in four categories.
- D. J. Tian, A. Bates, K. R. B. Butler, *Defending Against Malicious USB Firmware with GoodUSB*, ACSAC 2015.
  Basis for `device_type_mismatch` and `programmable_hid_board`.
- A. Kharraz, B. L. Daley, G. Z. Baker, W. Robertson, E. Kirda, *USBESAFE: An End-Point Solution to
  Protect Against USB-Based Attacks*, RAID 2019. Reports 95.7% detection at 0.21% false positives;
  the benchmark TraceForge's evaluation is compared with.
- K. Denney, E. Erdin, L. Babun, M. Vai, S. Uluagac, *USB-Watch: A Dynamic Hardware-Assisted USB Threat
  Detection Framework*, SecureComm 2019.
- S. Neuner et al., *USBlock: Blocking USB-Based Keypress Injection Attacks*, IFIP (Springer LNCS), 2018.
- G. Karantzas, *Forensic Log Based Detection For Keystroke Injection "BadUSB" Attacks*, arXiv:2302.04541 (2023).
  Detects injection by comparing keystroke bursts with human typing by inspection; TraceForge makes the
  thresholds explicit (rate, regularity, burst fraction).
- Honeywell GARD, *USB Threat Report 2024*. USB-borne malware rose from 9% (2019) to 51% of detections.
- Population Stability Index bands (0.10 / 0.25) used by `/ml/drift` are an industry convention from
  credit-risk model monitoring, not a formal standard.
