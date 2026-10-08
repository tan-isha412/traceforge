import { useState } from "react";
import { api, formatTime, usePolling } from "../api.js";
import RiskBadge from "./RiskBadge.jsx";
import Timeline from "./Timeline.jsx";

const STATUSES = ["open", "investigating", "resolved"];

export function IncidentTable({ incidents, selectedId, onSelect }) {
  if (!incidents) return <div className="empty">Loading incidents…</div>;
  if (incidents.length === 0) return <div className="empty">No incidents. Suspicious events will be grouped here.</div>;
  return (
    <div className="incident-list">
      {incidents.map((i) => (
        <button
          key={i.id}
          className={`incident ${i.id === selectedId ? "selected" : ""} ${i.status === "resolved" ? "resolved" : ""}`}
          onClick={() => onSelect(i.id)}
        >
          <div className="incident-head">
            <b>Incident #{i.id}</b>
            <span className="incident-badges">
              <span className={`chip status-${i.status}`}>{i.status}</span>
              <RiskBadge level={i.level} score={i.max_score} />
            </span>
          </div>
          <div>{i.devices.length > 1 ? `${i.devices.length} devices: ${i.devices.join(", ")}` : i.device_label}</div>
          <div className="muted small">
            on <span className="mono">{i.machines.join(", ")}</span> · {i.event_count} events · {formatTime(i.start_time)}
          </div>
          {i.case_machines.length > 1 && (
            <div className="small">
              <span className="chip chip-case">case #{i.case_id} · {i.case_machines.length} machines</span>
            </div>
          )}
        </button>
      ))}
    </div>
  );
}

function CaseSection({ incident, onSelectIncident }) {
  if (!incident.related.length) return null;
  return (
    <div className="card-section">
      <h3>Cross-machine case #{incident.case_id}</h3>
      <p className="muted small">{incident.case_reason}</p>
      <p className="small">
        Machines involved: <span className="mono">{incident.case_machines.join(", ")}</span>
      </p>
      <div className="incident-list">
        {incident.related.map((r) => (
          <button key={r.id} className="incident" onClick={() => onSelectIncident(r.id)}>
            <div className="incident-head">
              <b>Incident #{r.id}</b>
              <RiskBadge level={r.level} score={r.max_score} />
            </div>
            <div className="muted small">
              {r.device_label} on <span className="mono">{r.machine_hostname}</span> · {formatTime(r.start_time)}
            </div>
          </button>
        ))}
      </div>
    </div>
  );
}

function Workflow({ incident, onChanged }) {
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(null);
  const [note, setNote] = useState(incident.note || "");

  const save = async (changes) => {
    setSaving(true);
    setError(null);
    try {
      await api.updateIncident(incident.id, changes);
      onChanged();
    } catch (e) {
      setError(e.message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="card-section">
      <h3>Investigation</h3>
      <div className="segmented">
        {STATUSES.map((s) => (
          <button key={s} disabled={saving} className={incident.status === s ? "active" : ""} onClick={() => save({ status: s })}>
            {s}
          </button>
        ))}
      </div>
      <textarea
        className="note"
        rows={3}
        placeholder="Investigator notes…"
        value={note}
        maxLength={2000}
        onChange={(e) => setNote(e.target.value)}
      />
      <div className="row">
        <button className="btn" disabled={saving || note === (incident.note || "")} onClick={() => save({ note })}>
          Save note
        </button>
        {error && <span className="error small">{error}</span>}
      </div>
    </div>
  );
}

export function IncidentPanel({ incidentId, onOpenDevice, onSelectIncident, onChanged }) {
  const { data, refresh } = usePolling(() => api.incident(incidentId), incidentId);
  if (!data) return <div className="empty">Loading incident…</div>;
  return (
    <div>
      <div className="card-section">
        <h2>Incident #{data.id}</h2>
        <div className="meta">
          <span>{data.devices.join(" · ")}</span>
          <span>
            on <span className="mono">{data.machines.join(", ")}</span>
          </span>
          <span>
            {formatTime(data.start_time)} → {formatTime(data.end_time)}
          </span>
        </div>
        <button className="link" onClick={() => onOpenDevice(data.device_id)}>
          Open device profile →
        </button>
      </div>
      <CaseSection incident={data} onSelectIncident={onSelectIncident} />
      <Workflow
        key={data.id}
        incident={data}
        onChanged={() => {
          refresh();
          onChanged();
        }}
      />
      <div className="card-section">
        <h3>Correlated events</h3>
        <Timeline entries={data.timeline} />
      </div>
    </div>
  );
}
