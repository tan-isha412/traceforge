import { useMemo, useState } from "react";
import { formatTime } from "../api.js";
import RiskBadge from "./RiskBadge.jsx";

export default function DeviceList({ devices, selectedId, onSelect }) {
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState("all");

  const filtered = useMemo(() => {
    if (!devices) return [];
    const term = search.trim().toLowerCase();
    return devices.filter((d) => {
      if (filter === "high" && d.risk_level !== "critical" && d.risk_level !== "high") return false;
      if (filter === "unknown" && d.known) return false;
      if (filter === "known" && !d.known) return false;

      if (!term) return true;
      return (
        (d.device_type && d.device_type.toLowerCase().includes(term)) ||
        d.vendor_id.toLowerCase().includes(term) ||
        d.product_id.toLowerCase().includes(term) ||
        (d.serial_number && d.serial_number.toLowerCase().includes(term))
      );
    });
  }, [devices, search, filter]);

  if (!devices) return <div className="empty">Loading devices…</div>;
  if (devices.length === 0)
    return <div className="empty">No devices yet. Run the agent or seed the synthetic dataset.</div>;

  return (
    <div className="device-list-container">
      <div className="filter-toolbar">
        <div className="search-box">
          <input
            type="text"
            className="search-input"
            placeholder="Search vendor, model, serial…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          {search && (
            <button className="search-clear" onClick={() => setSearch("")} title="Clear search">
              ×
            </button>
          )}
        </div>
        <div className="filter-chips">
          <button
            className={`filter-btn ${filter === "all" ? "active" : ""}`}
            onClick={() => setFilter("all")}
          >
            All ({devices.length})
          </button>
          <button
            className={`filter-btn ${filter === "high" ? "active" : ""}`}
            onClick={() => setFilter("high")}
          >
            High/Critical
          </button>
          <button
            className={`filter-btn ${filter === "unknown" ? "active" : ""}`}
            onClick={() => setFilter("unknown")}
          >
            Unknown
          </button>
          <button
            className={`filter-btn ${filter === "known" ? "active" : ""}`}
            onClick={() => setFilter("known")}
          >
            Known
          </button>
        </div>
      </div>

      {filtered.length === 0 ? (
        <div className="empty">No devices match your search or filter.</div>
      ) : (
        <table className="table">
          <thead>
            <tr>
              <th>Device</th>
              <th>Status</th>
              <th>Machines</th>
              <th>Last seen</th>
              <th>Risk</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((d) => (
              <tr key={d.id} className={d.id === selectedId ? "selected" : ""} onClick={() => onSelect(d.id)}>
                <td>
                  <div className="device-name">{d.device_type || "Unknown type"}</div>
                  <div className="mono muted">
                    {d.vendor_id}:{d.product_id} · {d.serial_number || "no serial"}
                  </div>
                </td>
                <td>
                  <span className={`chip ${d.known ? "chip-known" : "chip-unknown"}`}>{d.known ? "known" : "unknown"}</span>
                </td>
                <td>{d.machine_count}</td>
                <td className="muted">{d.last_seen ? formatTime(d.last_seen) : "–"}</td>
                <td>
                  <RiskBadge level={d.risk_level} score={d.risk_score} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

