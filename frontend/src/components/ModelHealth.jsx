import { useState } from "react";
import { api, formatTime, usePolling } from "../api.js";

const STATUS = {
  healthy: ["Healthy", "low"],
  watch: ["Watch", "medium"],
  retrain_recommended: ["Retrain recommended", "critical"],
  insufficient_data: ["Not enough recent data", "none"],
  not_trained: ["Not trained", "none"],
  unknown: ["Unknown", "none"],
};
const BAND = { stable: "low", shifting: "medium", drifted: "critical" };
const ALGORITHMS = { iforest: "Isolation Forest", ocsvm: "One-Class SVM" };

// Has normal behaviour drifted away from what the model learned? PSI per feature against the training baseline.
export default function ModelHealth() {
  const [days, setDays] = useState(14);
  const { data, error } = usePolling(() => api.mlDrift(days), `drift-${days}`, 60000);
  if (error && !data) return <div className="empty">{error.message}</div>;
  if (!data) return <div className="empty">Checking the model…</div>;
  const [label, tone] = STATUS[data.status] || [data.status, "none"];
  const maxPsi = Math.max(0.3, ...data.features.map((f) => f.psi));

  return (
    <div>
      <div className="card-section">
        <div className="graph-toolbar">
          <h3>
            Model health <span className={`badge badge-${tone}`}>{label}</span>
          </h3>
          <span className="segmented">
            {[7, 14, 30].map((d) => (
              <button key={d} className={days === d ? "active" : ""} onClick={() => setDays(d)}>
                Last {d} days
              </button>
            ))}
          </span>
        </div>
        <ul className="health-reasons">
          {data.reasons.map((r) => (
            <li key={r}>{r}</li>
          ))}
        </ul>
        {data.algorithm && (
          <div className="meta">
            <span>{ALGORITHMS[data.algorithm] || data.algorithm}</span>
            <span>trained on {data.training_rows} connections</span>
            {data.trained_at && <span>{formatTime(data.trained_at)} ({data.model_age_days} days ago)</span>}
            <span>{data.recent_connections} normal connections in the window</span>
            {data.recent_outlier_rate !== undefined && (
              <span>
                outliers {Math.round(data.recent_outlier_rate * 100)}% (expected {Math.round(data.expected_outlier_rate * 100)}%)
              </span>
            )}
          </div>
        )}
        {data.status === "retrain_recommended" && (
          <p className="small health-hint">
            An admin can retrain from the server UI (<span className="mono">POST /ml/train</span> at <span className="mono">/docs</span>) or with{" "}
            <span className="mono">curl.exe -X POST http://localhost:8000/ml/train -H "X-API-Key: …"</span>. Connections in incidents are left out
            automatically.
          </p>
        )}
      </div>

      {data.features.length > 0 && (
        <div className="card-section">
          <h3>Drift per feature</h3>
          <p className="muted small">
            Population Stability Index of each feature in recent normal activity against the training baseline: under 0.10 stable,
            0.10 to 0.25 shifting, over 0.25 drifted.
          </p>
          <div className="table-scroll">
            <table className="table">
              <thead>
                <tr>
                  <th>Feature</th>
                  <th>PSI</th>
                  <th></th>
                  <th>Training median</th>
                  <th>Recent median</th>
                </tr>
              </thead>
              <tbody>
                {data.features.map((f) => (
                  <tr key={f.feature}>
                    <td>{f.label}</td>
                    <td className="mono">{f.psi}</td>
                    <td className="psi-cell">
                      <span className={`psi-bar psi-${BAND[f.band]}`} style={{ width: `${Math.min(100, (f.psi / maxPsi) * 100)}%` }} />
                      <span className={`badge badge-${BAND[f.band]}`}>{f.band}</span>
                    </td>
                    <td className="mono">{f.training_median}</td>
                    <td className="mono">{f.recent_median}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
