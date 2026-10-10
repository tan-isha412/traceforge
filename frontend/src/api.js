import { useEffect, useRef, useState } from "react";

export const API_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";

async function request(path, options) {
  const res = await fetch(`${API_URL}${path}`, options);
  if (!res.ok) {
    let detail = `${res.status} ${path}`;
    try {
      detail = (await res.json()).detail || detail;
    } catch {
      /* keep the status line */
    }
    throw new Error(detail);
  }
  return res.json();
}

const get = (path) => request(path);
const send = (method, path, body) =>
  request(path, { method, headers: { "Content-Type": "application/json" }, body: body && JSON.stringify(body) });

export const api = {
  stats: () => get("/stats"),
  devices: (params) => {
    if (!params) return get("/devices");
    const qs = new URLSearchParams();
    if (params.q) qs.set("q", params.q);
    if (params.risk_level) qs.set("risk_level", params.risk_level);
    if (params.known !== undefined && params.known !== null) qs.set("known", params.known);
    const query = qs.toString();
    return get(query ? `/devices?${query}` : "/devices");
  },
  device: (id) => get(`/devices/${id}`),
  timeline: (id) => get(`/devices/${id}/timeline`),
  riskHistory: (id) => get(`/risk-scores/${id}`),
  exportDeviceUrl: (id, format = "json") => `${API_URL}/devices/${id}/export?format=${format}`,
  incidents: () => get("/incidents"),
  incident: (id) => get(`/incidents/${id}`),
  updateIncident: (id, changes) => send("PATCH", `/incidents/${id}`, changes),
};

// Re-runs `load` every `ms`; returns { data, error, refresh }. `key` resets the data when the target changes.
export function usePolling(load, key, ms = 3000) {
  const [state, setState] = useState({ data: null, error: null });
  const tickRef = useRef(null);

  useEffect(() => {
    let alive = true;
    setState({ data: null, error: null });
    const tick = async () => {
      try {
        const data = await load();
        if (alive) setState({ data, error: null });
      } catch (error) {
        if (alive) setState((s) => ({ ...s, error }));
      }
    };
    tickRef.current = tick;
    tick();
    const timer = setInterval(tick, ms);
    return () => {
      alive = false;
      clearInterval(timer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, ms]);

  return { ...state, refresh: () => tickRef.current?.() };
}

// The API sends UTC; every time is shown in this zone regardless of the browser's setting.
export const DISPLAY_TZ = import.meta.env.VITE_TIMEZONE || "Asia/Kolkata";

export const formatTime = (iso) =>
  new Date(/[zZ]|[+-]\d\d:\d\d$/.test(iso) ? iso : `${iso}Z`).toLocaleString("en-IN", {
    timeZone: DISPLAY_TZ,
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
