import { useCallback, useEffect, useState } from "react";
import { API_URL, DISPLAY_TZ, api, setToken, usePolling } from "./api.js";
import AuditLog from "./components/AuditLog.jsx";
import DeviceList from "./components/DeviceList.jsx";
import DevicePanel from "./components/DevicePanel.jsx";
import EvidenceImport from "./components/EvidenceImport.jsx";
import GraphView from "./components/GraphView.jsx";
import ModelHealth from "./components/ModelHealth.jsx";
import { IncidentPanel, IncidentTable } from "./components/IncidentList.jsx";
import Login from "./components/Login.jsx";
import StatCards from "./components/StatCards.jsx";

const ALGORITHMS = { iforest: "Isolation Forest", ocsvm: "One-Class SVM" };

function EvidenceChip({ result }) {
  if (!result) return null;
  if (result.intact)
    return (
      <span className="chip chip-known" title={`Hash chain head ${result.chain_head}`}>
        ✓ Evidence intact · {result.events_checked} events
      </span>
    );
  return (
    <span className="chip chip-tampered" title={result.problem}>
      ⚠ Evidence tampered at event #{result.first_broken_event_id}
    </span>
  );
}

// Decides between the login screen and the dashboard. With logins switched off on the server,
// the dashboard opens straight away, as before.
export default function App() {
  const [auth, setAuth] = useState({ checked: false, enabled: false, user: null });

  const check = useCallback(async () => {
    try {
      const { auth_enabled } = await api.authConfig();
      const user = auth_enabled ? await api.me().catch(() => null) : null;
      setAuth({ checked: true, enabled: auth_enabled, user });
    } catch {
      setAuth({ checked: true, enabled: false, user: null }); // server offline: the dashboard shows the banner
    }
  }, []);

  useEffect(() => {
    check();
    const onLoggedOut = () => {
      setToken(null);
      setAuth((a) => ({ ...a, user: null }));
    };
    window.addEventListener("traceforge:logged-out", onLoggedOut);
    return () => window.removeEventListener("traceforge:logged-out", onLoggedOut);
  }, [check]);

  if (!auth.checked) return <div className="empty">Connecting…</div>;
  if (auth.enabled && !auth.user)
    return (
      <Login
        onLoggedIn={(result) => {
          setToken(result.token);
          setAuth({ checked: true, enabled: true, user: { username: result.username, role: result.role } });
        }}
      />
    );

  const logout = async () => {
    await api.logout().catch(() => {});
    setToken(null);
    setAuth((a) => ({ ...a, user: null }));
  };
  return <Dashboard user={auth.enabled ? auth.user : null} onLogout={logout} />;
}

function Dashboard({ user, onLogout }) {
  const [tab, setTab] = useState("devices");
  const [deviceId, setDeviceId] = useState(null);
  const [incidentId, setIncidentId] = useState(null);

  const stats = usePolling(api.stats, "stats");
  const devices = usePolling(api.devices, "devices");
  const incidents = usePolling(api.incidents, "incidents");
  const integrity = usePolling(api.integrity, "integrity", 15000);
  const ml = usePolling(api.mlStatus, "ml", 15000);

  const offline = stats.error && !stats.data;
  const isAdmin = user?.role === "admin";

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
          <EvidenceChip result={integrity.data} />
          <span
            className={`chip ${ml.data?.trained ? "chip-known" : "chip-unknown"}`}
            title={ml.data?.trained ? `Trained on ${ml.data.training_rows} connections (${ml.data.excluded_rows} suspicious left out)` : "Rules only until the model is trained"}
          >
            {ALGORITHMS[ml.data?.algorithm] || "ML"} · {ml.data?.trained ? "trained" : "not trained"}
          </span>
          <span className={`live ${offline ? "live-off" : ""}`}>{offline ? "server offline" : "live"}</span>
          {user && (
            <span className="user-menu">
              <span className="chip" title={`Signed in as ${user.role}`}>
                {user.username} · {user.role}
              </span>
              <button className="btn btn-sm" onClick={onLogout}>
                Log out
              </button>
            </span>
          )}
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
        <button className={tab === "graph" ? "active" : ""} onClick={() => setTab("graph")}>
          Attack graph
        </button>
        <button className={tab === "evidence" ? "active" : ""} onClick={() => setTab("evidence")}>
          Evidence import
        </button>
        <button className={tab === "model" ? "active" : ""} onClick={() => setTab("model")}>
          Model health
        </button>
        {isAdmin && (
          <button className={tab === "audit" ? "active" : ""} onClick={() => setTab("audit")}>
            Audit log
          </button>
        )}
      </nav>

      {["audit", "graph", "evidence", "model"].includes(tab) ? (
        <section className="pane">
          {tab === "audit" && <AuditLog />}
          {tab === "graph" && <GraphView />}
          {tab === "evidence" && <EvidenceImport />}
          {tab === "model" && <ModelHealth />}
        </section>
      ) : (
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
            {tab === "incidents" && incidentId && (
              <IncidentPanel
                incidentId={incidentId}
                onOpenDevice={openDevice}
                onSelectIncident={setIncidentId}
                onChanged={() => {
                  incidents.refresh();
                  stats.refresh();
                }}
              />
            )}
            {((tab === "devices" && !deviceId) || (tab === "incidents" && !incidentId)) && (
              <div className="empty">Select {tab === "devices" ? "a device" : "an incident"} to investigate.</div>
            )}
          </section>
        </main>
      )}
    </div>
  );
}
