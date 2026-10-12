import { formatTime } from "../api.js";
import MitreChips from "./MitreChips.jsx";
import RiskBadge from "./RiskBadge.jsx";

const bytes = (n) => {
  if (!n) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.min(Math.floor(Math.log(n) / Math.log(1024)), units.length - 1);
  return `${(n / 1024 ** i).toFixed(i < 2 ? 0 : 1)} ${units[i]}`;
};

function Drivers({ drivers }) {
  const max = Math.max(...drivers.map((d) => Math.abs(d.shap_value)), 1e-9);
  return (
    <div className="drivers">
      {drivers.map((d) => (
        <div key={d.feature} className="driver">
          <div className="driver-text">{d.text}</div>
          <div className="driver-bar">
            <span style={{ width: `${(Math.abs(d.shap_value) / max) * 100}%` }} />
          </div>
          <div className="mono muted">SHAP {d.shap_value}</div>
        </div>
      ))}
    </div>
  );
}

function Anomaly({ a }) {
  return (
    <div className={`anomaly anomaly-${a.source}`}>
      <div className="anomaly-head">
        <span className={`chip chip-${a.source}`}>{a.source === "ml" ? (a.detail?.drivers ? "ML · SHAP" : "ML") : "rule"}</span>
        <span className="mono">{a.name}</span>
        <span className="muted">+{a.weight}</span>
        <MitreChips techniques={a.mitre} />
      </div>
      <div>{a.explanation}</div>
      {a.detail?.drivers?.length > 0 && <Drivers drivers={a.detail.drivers} />}
    </div>
  );
}

export default function Timeline({ entries }) {
  if (!entries) return <div className="empty">Loading timeline…</div>;
  if (entries.length === 0) return <div className="empty">No events recorded.</div>;

  // Newest first reads best for an investigator; the API returns oldest first.
  const rows = [...entries].reverse();
  return (
    <ol className="timeline">
      {rows.map((e) => (
        <li key={e.event_id} className={`tl-item tl-${e.risk_level || "none"}`}>
          <div className="tl-dot" />
          <div className="tl-body">
            <div className="tl-head">
              <b>{{ connect: "Connected", disconnect: "Disconnected", typing: "Typing report" }[e.event_type] || e.event_type}</b>
              <span className="muted">
                on <span className="mono">{e.machine_hostname}</span>
              </span>
              <RiskBadge level={e.risk_level} score={e.risk_score} />
            </div>
            <div className="muted small">
              {formatTime(e.timestamp)}
              {e.transfer && ` · wrote ${bytes(e.transfer.bytes_written)}, read ${bytes(e.transfer.bytes_read)}`}
              {e.source && ` · ${e.source.replace("import:", "imported from ")}`}
              {e.record_hash && (
                <span className="mono evidence-hash" title={`Evidence hash ${e.record_hash}`}>
                  {" "}· sha256 {e.record_hash.slice(0, 12)}…
                </span>
              )}
            </div>
            {e.anomalies.map((a) => (
              <Anomaly key={a.id} a={a} />
            ))}
          </div>
        </li>
      ))}
    </ol>
  );
}
