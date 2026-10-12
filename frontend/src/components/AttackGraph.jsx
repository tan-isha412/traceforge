import { useEffect, useMemo, useState } from "react";
import { formatTime } from "../api.js";

// Devices on the left, machines on the right, one link per device-machine pair coloured by the
// worst risk seen on it. The replay reveals connections in time order, so an attack can be
// watched spreading from machine to machine.

const ROW = 48;
const TOP = 36;
const DEV_X = 24;
const MACH_X = 560;
const NODE_W = 216;
const NODE_H = 36;
const LEVELS = ["low", "medium", "high", "critical"];
const SPEEDS = [1, 3, 8];

const worse = (a, b) => (LEVELS.indexOf(b) > LEVELS.indexOf(a) ? b : a);
const short = (s, n) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);

export default function AttackGraph({ data, autoplay = false }) {
  const total = data.events.length;
  const [step, setStep] = useState(autoplay ? 0 : total);
  const [playing, setPlaying] = useState(autoplay);
  const [speed, setSpeed] = useState(1);

  // Start over only when the set of events changes, not on every background refresh.
  useEffect(() => {
    setStep(autoplay ? 0 : total);
    setPlaying(autoplay);
  }, [data.title, autoplay, total]);

  useEffect(() => {
    if (!playing) return undefined;
    if (step >= total) {
      setPlaying(false);
      return undefined;
    }
    const timer = setTimeout(() => setStep((s) => s + 1), 900 / speed);
    return () => clearTimeout(timer);
  }, [playing, step, total, speed]);

  const pos = useMemo(() => {
    const rows = Math.max(data.devices.length, data.machines.length, 1);
    const spread = (list, i) => TOP + ((rows - list.length) * ROW) / 2 + i * ROW;
    return {
      device: Object.fromEntries(data.devices.map((d, i) => [d.id, spread(data.devices, i)])),
      machine: Object.fromEntries(data.machines.map((m, i) => [m.id, spread(data.machines, i)])),
      height: TOP + rows * ROW,
    };
  }, [data]);

  const shown = data.events.slice(0, step);
  const current = step > 0 ? data.events[step - 1] : null;
  const links = {};
  const reached = { device: {}, machine: {} };
  for (const e of shown) {
    const key = `${e.device_id}-${e.machine_id}`;
    const link = (links[key] ||= { device: e.device_id, machine: e.machine_id, count: 0, level: "low" });
    link.count += 1;
    link.level = worse(link.level, e.risk_level);
    reached.device[e.device_id] = worse(reached.device[e.device_id] || "low", e.risk_level);
    reached.machine[e.machine_id] = worse(reached.machine[e.machine_id] || "low", e.risk_level);
  }
  const device = (id) => data.devices.find((d) => d.id === id);
  const machine = (id) => data.machines.find((m) => m.id === id);

  if (total === 0) return <div className="empty">No connections in this period.</div>;

  return (
    <div className="attack-graph">
      <div className="graph-controls">
        <button className="btn btn-sm" onClick={() => { setStep(0); setPlaying(true); }} title="Replay from the start">
          ⏮ Replay
        </button>
        <button className="btn btn-sm" onClick={() => (step >= total ? (setStep(0), setPlaying(true)) : setPlaying((p) => !p))}>
          {playing ? "⏸ Pause" : "▶ Play"}
        </button>
        <input
          className="graph-slider"
          type="range"
          min={0}
          max={total}
          value={step}
          onChange={(e) => {
            setPlaying(false);
            setStep(Number(e.target.value));
          }}
          aria-label="Replay position"
        />
        <span className="muted small mono">
          {step}/{total}
        </span>
        <span className="segmented graph-speed">
          {SPEEDS.map((s) => (
            <button key={s} className={speed === s ? "active" : ""} onClick={() => setSpeed(s)}>
              {s}×
            </button>
          ))}
        </span>
      </div>

      <div className={`graph-caption ${current ? `graph-caption-${current.risk_level}` : ""}`}>
        {current ? (
          <>
            <b>{formatTime(current.timestamp)}</b> · {{ connect: "connected", disconnect: "disconnected", typing: "typed on" }[current.event_type] || current.event_type}{" "}
            <span className="mono">{device(current.device_id)?.label}</span> → <span className="mono">{machine(current.machine_id)?.hostname}</span> ·{" "}
            {current.risk_level} {Math.round(current.risk_score)}
            {current.findings.length > 0 && <span className="muted"> · {current.findings.join(", ")}</span>}
            {current.mitre.length > 0 && <span className="mono graph-mitre"> {current.mitre.join(" ")}</span>}
          </>
        ) : (
          <span className="muted">Press play to watch the connections in time order.</span>
        )}
      </div>

      <svg className="graph-svg" viewBox={`0 0 800 ${pos.height}`} role="img" aria-label={data.title || "Device to machine attack graph"}>
        <text x={DEV_X} y={20} className="graph-heading">
          Devices
        </text>
        <text x={MACH_X} y={20} className="graph-heading">
          Machines
        </text>
        {Object.entries(links).map(([key, l]) => {
          const y1 = pos.device[l.device] + NODE_H / 2;
          const y2 = pos.machine[l.machine] + NODE_H / 2;
          const x1 = DEV_X + NODE_W;
          const x2 = MACH_X;
          const isCurrent = current && key === `${current.device_id}-${current.machine_id}`;
          return (
            <path
              key={key}
              d={`M${x1} ${y1} C${x1 + 110} ${y1}, ${x2 - 110} ${y2}, ${x2} ${y2}`}
              className={`graph-link link-${l.level} ${isCurrent ? "link-current" : ""}`}
              strokeWidth={1.5 + Math.min(4, Math.log2(l.count + 1))}
            >
              <title>{`${l.count} event(s), worst ${l.level}`}</title>
            </path>
          );
        })}
        {data.devices.map((d) => {
          const lvl = reached.device[d.id];
          const active = current?.device_id === d.id;
          return (
            <g key={`d${d.id}`} className={`graph-node ${lvl ? `node-${lvl}` : "node-idle"} ${active ? "node-active" : ""}`}>
              <rect x={DEV_X} y={pos.device[d.id]} width={NODE_W} height={NODE_H} rx="8" />
              <text x={DEV_X + 10} y={pos.device[d.id] + 15} className="graph-label">
                {short(d.label, 30)}
              </text>
              <text x={DEV_X + 10} y={pos.device[d.id] + 29} className="graph-sub">
                {d.serial_number ? short(d.serial_number, 18) : "no serial"} · {d.trust_level}
              </text>
            </g>
          );
        })}
        {data.machines.map((m) => {
          const lvl = reached.machine[m.id];
          const active = current?.machine_id === m.id;
          return (
            <g key={`m${m.id}`} className={`graph-node ${lvl ? `node-${lvl}` : "node-idle"} ${active ? "node-active" : ""}`}>
              <rect x={MACH_X} y={pos.machine[m.id]} width={NODE_W} height={NODE_H} rx="8" />
              <text x={MACH_X + 10} y={pos.machine[m.id] + 23} className="graph-label">
                {m.hostname}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}
