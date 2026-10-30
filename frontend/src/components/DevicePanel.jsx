import { useState } from "react";
import { api, saveFile, usePolling, verifySignature } from "../api.js";
import RiskBadge from "./RiskBadge.jsx";
import { riskLabel, riskTone } from "../risk.js";
import Timeline from "./Timeline.jsx";
import TrustBadge from "./TrustBadge.jsx";

function ExportActions({ device: d }) {
  const [result, setResult] = useState(null);
  const run = async (format, filename) => {
    try {
      const out = await api.exportDevice(d.id, format, filename);
      let verified = null;
      let publicKey = null;
      if (out.signature) {
        publicKey = await api.publicKey();
        verified = await verifySignature(
          out.bytes,
          out.signature,
          publicKey.public_key_pem,
        );
      }
      setResult({ filename, ...out, verified, publicKey });
    } catch (e) {
      setResult({ error: e.message });
    }
  };
  // The signature travels in response headers; save it next to the report so it can be checked later.
  const saveSignature = () =>
    saveFile(
      JSON.stringify(
        {
          algorithm: result.algorithm,
          key_id: result.keyId,
          sha256: result.sha256,
          signature: result.signature,
          file: result.filename,
        },
        null,
        2,
      ),
      `${result.filename}.sig`,
      "application/json",
    );
  const savePublicKey = () =>
    saveFile(
      result.publicKey.public_key_pem,
      "traceforge_public.pem",
      "application/x-pem-file",
    );
  return (
    <>
      <div className="export-actions">
        <button
          className="btn btn-sm"
          title="Download complete forensic JSON dossier"
          onClick={() =>
            run("json", `forensic_report_${d.vendor_id}_${d.product_id}.json`)
          }
        >
          Export JSON
        </button>
        <button
          className="btn btn-sm"
          title="Download event timeline CSV"
          onClick={() =>
            run("csv", `timeline_${d.vendor_id}_${d.product_id}.csv`)
          }
        >
          Export CSV
        </button>
      </div>
      {/* Own full-width row under the header, so the hash and signature never squeeze the device title. */}
      {(result?.sha256 || result?.error) && (
        <div className="export-result">
          {result?.sha256 && (
            <div
              className="muted small export-hash"
              title="Keep this to prove later that the saved file is unchanged"
            >
              {result.filename} · SHA-256{" "}
              <span className="mono">{result.sha256}</span>
            </div>
          )}
          {result?.signature && (
            <div className="signature-box small">
              {result.verified === true && (
                <span
                  className="sig-ok"
                  title="RSA-PSS-SHA256 signature checked in this browser against the server's public key"
                >
                  ✓ Signature valid · key{" "}
                  <span className="mono">{result.keyId}</span>
                </span>
              )}
              {result.verified === false && (
                <span className="sig-bad">
                  ✗ Signature does not match: do not rely on this file
                </span>
              )}
              {result.verified === null && (
                <span className="muted">
                  Signed with key {result.keyId}; verify offline with
                  tools/verify_signature.py
                </span>
              )}
              <span className="sig-actions">
                <button className="link-btn" onClick={saveSignature}>
                  Save .sig
                </button>
                <button className="link-btn" onClick={savePublicKey}>
                  Public key
                </button>
              </span>
            </div>
          )}
          {result?.error && <div className="error small">{result.error}</div>}
        </div>
      )}
    </>
  );
}

const OVERRIDES = [
  ["auto", "Auto"],
  ["trusted", "Trusted"],
  ["blocklisted", "Blocklisted"],
];

function TrustSection({ device, onChanged }) {
  const [note, setNote] = useState(device.trust_note || "");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(null);

  const save = async (status) => {
    setSaving(true);
    setError(null);
    try {
      await api.setTrust(device.id, status, note);
      onChanged();
    } catch (e) {
      setError(e.message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="card-section">
      <h3>
        Device trust{" "}
        <TrustBadge
          level={device.trust_level}
          score={device.trust_score}
          status={device.trust_status}
        />
      </h3>
      <ul className="factors">
        {device.trust_factors.map((f) => (
          <li key={f.factor}>
            <span
              className={`factor-weight ${f.weight < 0 ? "factor-negative" : ""}`}
            >
              {f.weight > 0 ? `+${f.weight}` : f.weight}
            </span>
            <div>
              <div className="mono">{f.factor}</div>
              <div className="muted small">{f.explanation}</div>
            </div>
          </li>
        ))}
      </ul>
      <p className="muted small">
        Trusted silences the "new machine" alert for a device that moves between
        machines; clone, descriptor and behaviour checks still apply.
        Blocklisted flags every future connection. Nothing is blocked on the
        machine.
      </p>
      <input
        className="search-input trust-note"
        placeholder="Reason (optional), e.g. reported stolen"
        value={note}
        maxLength={500}
        onChange={(e) => setNote(e.target.value)}
      />
      <div className="segmented">
        {OVERRIDES.map(([value, label]) => (
          <button
            key={value}
            disabled={saving}
            className={device.trust_status === value ? "active" : ""}
            onClick={() => save(value)}
          >
            {label}
          </button>
        ))}
      </div>
      {error && <div className="error small">{error}</div>}
    </div>
  );
}

function RiskBreakdown({ history }) {
  // The device's current risk. Typing reports and disconnects carry their attachment's factors
  // (tagged carried_from); rows stored by older versions only say "inherited", so skip those.
  const latest = history?.find((h) => h.reasoning[0]?.factor !== "inherited");
  if (!latest) return null;
  return (
    <div className="card-section">
      <h3>
        Risk score <RiskBadge level={latest.level} score={latest.score} />
      </h3>
      <ul className="factors">
        {latest.reasoning.map((r, i) => (
          <li key={`${r.factor}-${i}`}>
            <span className="factor-weight">+{r.weight}</span>
            <div>
              <div className="mono">
                {r.factor}
                {r.carried_from && (
                  <span className="muted small">
                    {" "}
                    (from event #{r.carried_from})
                  </span>
                )}
              </div>
              <div className="muted small">{r.explanation}</div>
              {r.nist && <NistLine n={r.nist} />}
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}

function NistLine({ n }) {
  // The Sigma rule's NIST SP 800-30 assessment: likelihood x impact, Table I-2 level of risk.
  const label = (level) => riskLabel(level).replace(/^./, (c) => c.toUpperCase());
  return (
    <div className="standard-line small" title={n.rationale}>
      <span className={`rating rating-${riskTone(n.risk_level)}`}>NIST {label(n.risk_level)}</span>
      <span>
        likelihood {n.likelihood} ({label(n.likelihood_level)}) x impact {n.impact} ({label(n.impact_level)})
      </span>
      <span className="muted">Sigma: {n.rule}</span>
    </div>
  );
}

function DescriptorSection({ descriptor }) {
  if (!descriptor) return null;
  const interfaces = descriptor.interfaces || [];
  return (
    <div className="card-section">
      <h3>USB descriptor profile</h3>
      <div className="meta">
        {descriptor.fingerprint ? (
          <span>
            fingerprint <span className="mono">{descriptor.fingerprint}</span>
          </span>
        ) : (
          <span className="muted">
            no structural fingerprint (agent could not read the descriptor tree)
          </span>
        )}
        {descriptor.bcd_usb && (
          <span className="mono">USB {descriptor.bcd_usb}</span>
        )}
        {descriptor.pnp_class && (
          <span className="mono">{descriptor.pnp_class}</span>
        )}
        {descriptor.service && (
          <span className="mono">{descriptor.service}</span>
        )}
      </div>
      {interfaces.length > 0 && (
        <ul className="factors">
          {interfaces.map((i, n) => (
            <li key={n}>
              <span className="factor-weight mono">
                #{i.interface_number ?? n}
              </span>
              <div>
                <div className="mono">
                  class 0x
                  {Number(i.interface_class).toString(16).padStart(2, "0")} /
                  sub {i.interface_subclass} / proto {i.interface_protocol}
                </div>
                <div className="muted small mono">
                  {(i.endpoints || [])
                    .map(
                      (e) =>
                        `${e.direction} ${e.transfer_type} ${e.max_packet_size}B`,
                    )
                    .join(" · ") || "no endpoints"}
                </div>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

export default function DevicePanel({ deviceId }) {
  const device = usePolling(() => api.device(deviceId), deviceId);
  const timeline = usePolling(() => api.timeline(deviceId), deviceId);
  const risk = usePolling(() => api.riskHistory(deviceId), deviceId);
  const d = device.data;

  return (
    <div>
      {d && (
        <div className="card-section">
          <div className="device-header-row">
            <div>
              <h2>{d.device_type || "Unknown device"}</h2>
              <div className="meta">
                <span className="mono">
                  {d.vendor_id}:{d.product_id}
                </span>
                <span className="mono">serial {d.serial_number || "none"}</span>
                <span>{d.event_count} events</span>
                <span>seen on {d.machines.join(", ")}</span>
              </div>
            </div>
            <ExportActions device={d} />
          </div>
        </div>
      )}
      {d && <TrustSection key={d.id} device={d} onChanged={device.refresh} />}
      <RiskBreakdown history={risk.data} />
      <DescriptorSection descriptor={d?.descriptor_json} />
      <div className="card-section">
        <h3>Timeline</h3>
        <Timeline entries={timeline.data} />
      </div>
    </div>
  );
}
