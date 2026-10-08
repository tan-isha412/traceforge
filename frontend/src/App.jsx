import { useState } from "react";
import { API_URL, DISPLAY_TZ, api, usePolling } from "./api.js";
import DeviceList from "./components/DeviceList.jsx";
import DevicePanel from "./components/DevicePanel.jsx";
import { IncidentPanel, IncidentTable } from "./components/IncidentList.jsx";
import StatCards from "./components/StatCards.jsx";

export default function App() {
  const [tab, setTab] = useState("devices");
  const [deviceId, setDeviceId] = useState(null);
  const [incidentId, setIncidentId] = useState(null);
  const [training, setTraining] = useState(null); // null | "running" | message

  const stats = usePolling(api.stats, "stats");
  const devices = usePolling(api.devices, "devices");
  const incidents = usePolling(api.incidents, "incidents");

  const offline = stats.error && !stats.data;

  const retrain = async () => {
    setTraining("running");
    try {
      const status = await api.train();
      setTraining(`Model retrained on ${status.training_rows} events`);
      stats.refresh();
    } catch (e) {
      setTraining(e.message);
    }
  };
  const openDevice = (id) => {
    setDeviceId(id);
    setTab("devices");
  };

  return (
    <div className="app">
      <header className="header">
        <div>
          <h1>TraceForge</h1>
          <p className="muted">USB forensic investigation and device trust analysis · times in {DISPLAY_TZ}</p>
        </div>
        <div className="header-status">
          {training && training !== "running" && <span className="muted small">{training}</span>}
          <button className="btn" disabled={training === "running"} onClick={retrain}>
            {training === "running" ? "Training…" : "Retrain model"}
          </button>
          <span className={`chip ${stats.data?.ml_trained ? "chip-known" : "chip-unknown"}`}>
            ML model {stats.data?.ml_trained ? "trained" : "not trained"}
          </span>
          <span className={`live ${offline ? "live-off" : ""}`}>{offline ? "server offline" : "live"}</span>
        </div>
      </header>

      {offline && (
        <div className="banner">
          Cannot reach the TraceForge server at <span className="mono">{API_URL}</span>. Start it with{" "}
          <span className="mono">uvicorn server.main:app</span>.
        </div>
      )}

      <StatCards stats={stats.data} />

      <nav className="tabs">
        <button className={tab === "devices" ? "active" : ""} onClick={() => setTab("devices")}>
          Devices
        </button>
        <button className={tab === "incidents" ? "active" : ""} onClick={() => setTab("incidents")}>
          Incidents{incidents.data?.length ? ` (${incidents.data.length})` : ""}
        </button>
      </nav>

      <main className="split">
        <section className="pane">
          {tab === "devices" ? (
            <DeviceList devices={devices.data} selectedId={deviceId} onSelect={setDeviceId} />
          ) : (
            <IncidentTable incidents={incidents.data} selectedId={incidentId} onSelect={setIncidentId} />
          )}
        </section>
        <section className="pane detail">
          {tab === "devices" && deviceId && <DevicePanel deviceId={deviceId} />}
<<<<<<< Updated upstream
          {tab === "incidents" && incidentId && <IncidentPanel incidentId={incidentId} onOpenDevice={openDevice} onSelectIncident={setIncidentId} />}
=======
          {tab === "incidents" && incidentId && <IncidentPanel
              incidentId={incidentId}
              onOpenDevice={openDevice}
              onChanged={() => {
                incidents.refresh();
                stats.refresh();
              }}
            />}
>>>>>>> Stashed changes
          {((tab === "devices" && !deviceId) || (tab === "incidents" && !incidentId)) && (
            <div className="empty">Select {tab === "devices" ? "a device" : "an incident"} to investigate.</div>
          )}
        </section>
      </main>
    </div>
  );
}
