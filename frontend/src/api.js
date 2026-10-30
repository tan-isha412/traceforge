import { useEffect, useRef, useState } from "react";

export const API_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";

// The login token lives for this browser tab only (sessionStorage), so closing the tab logs out.
const TOKEN_KEY = "traceforge-token";
export function getToken() {
  try {
    return sessionStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}
export function setToken(token) {
  try {
    if (token) sessionStorage.setItem(TOKEN_KEY, token);
    else sessionStorage.removeItem(TOKEN_KEY);
  } catch {
    /* storage unavailable: the session just won't survive a reload */
  }
}

const withAuth = (options = {}) => {
  const token = getToken();
  return token ? { ...options, headers: { ...options.headers, Authorization: `Bearer ${token}` } } : options;
};

async function request(path, options) {
  const res = await fetch(`${API_URL}${path}`, withAuth(options));
  if (res.status === 401 && getToken()) window.dispatchEvent(new Event("traceforge:logged-out"));
  if (!res.ok) {
    let detail = `${res.status} ${path}`;
    try {
      detail = (await res.json()).detail || detail;
    } catch {
      /* keep the status line */
    }
    throw new Error(detail);
  }
  return res.status === 204 ? null : res.json();
}

export function saveFile(data, filename, type = "application/octet-stream") {
  const url = URL.createObjectURL(data instanceof Blob ? data : new Blob([data], { type }));
  const a = Object.assign(document.createElement("a"), { href: url, download: filename });
  a.click();
  URL.revokeObjectURL(url);
}

// Downloads an export with the login token. Returns the exact bytes plus the server's SHA-256 and
// RSA-PSS signature for them, so the dashboard can verify the signature before anyone relies on it.
async function download(path, filename) {
  const res = await fetch(`${API_URL}${path}`, withAuth());
  if (!res.ok) throw new Error(`${res.status} ${path}`);
  const bytes = await res.arrayBuffer();
  saveFile(new Blob([bytes], { type: res.headers.get("Content-Type") || "application/octet-stream" }), filename);
  return {
    bytes,
    sha256: res.headers.get("X-Content-SHA256"),
    signature: res.headers.get("X-Signature"),
    algorithm: res.headers.get("X-Signature-Algorithm"),
    keyId: res.headers.get("X-Signature-Key-Id"),
  };
}

const b64ToBytes = (b64) => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));

// Verifies an RSA-PSS-SHA256 signature in the browser (WebCrypto) against the server's public key.
// Returns true/false, or null where WebCrypto is unavailable (pages served over plain http from
// another machine): then verify offline with tools/verify_signature.py.
export async function verifySignature(bytes, signatureB64, publicKeyPem) {
  if (!globalThis.crypto?.subtle) return null;
  const der = b64ToBytes(publicKeyPem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""));
  const key = await crypto.subtle.importKey("spki", der, { name: "RSA-PSS", hash: "SHA-256" }, false, ["verify"]);
  return crypto.subtle.verify({ name: "RSA-PSS", saltLength: 32 }, key, b64ToBytes(signatureB64), bytes);
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
  exportDevice: (id, format, filename) => download(`/devices/${id}/export?format=${format}`, filename),
  incidents: () => get("/incidents"),
  incident: (id) => get(`/incidents/${id}`),
  incidentStory: (id) => get(`/incidents/${id}/story`),
  updateIncident: (id, changes) => send("PATCH", `/incidents/${id}`, changes),
  setTrust: (id, status, note) => send("PUT", `/devices/${id}/trust`, { status, note: note || null }),
  integrity: () => get("/integrity/verify"),
  attestation: () => get("/integrity/attestation"),
  publicKey: () => get("/signing/public-key"),
  graph: (params) => get(`/graph?${new URLSearchParams(params)}`),
  importEvidence: (body) => send("POST", "/evidence/import", body),
  evidenceImports: () => get("/evidence/imports"),
  mlStatus: () => get("/ml/status"),
  mlDrift: (days) => get(`/ml/drift?days=${days}`),
  authConfig: () => get("/auth/config"),
  login: (username, password) => send("POST", "/auth/login", { username, password }),
  logout: () => send("POST", "/auth/logout"),
  me: () => get("/auth/me"),
  audit: () => get("/audit"),
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
