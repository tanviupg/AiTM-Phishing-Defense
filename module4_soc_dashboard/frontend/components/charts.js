/**
 * Zero-dependency interactive SVG chart components for Module 4 SOC Analytics.
 */
import { escapeHtml } from "./utils.js";

const PALETTE = {
  Critical: "#ef4444",
  High: "#f97316",
  Medium: "#f59e0b",
  Low: "#10b981",
  Open: "#ef4444",
  Investigating: "#f59e0b",
  Contained: "#8b5cf6",
  Resolved: "#10b981",
};

export function renderDonutChart(container, items, emptyText = "No data") {
  if (!container) return;
  const total = items.reduce((sum, d) => sum + (d.value || 0), 0);
  if (total === 0) {
    container.innerHTML = `<div class="card-subtitle">${escapeHtml(emptyText)}</div>`;
    return;
  }

  const radius = 58;
  const circumference = 2 * Math.PI * radius;
  let offset = 0;

  const segments = items
    .filter((d) => d.value > 0)
    .map((d) => {
      const frac = d.value / total;
      const dash = frac * circumference;
      const color = PALETTE[d.label] || "#00e5ff";
      const seg = `
        <circle
          cx="80" cy="80" r="${radius}"
          fill="transparent"
          stroke="${color}"
          stroke-width="20"
          stroke-dasharray="${dash.toFixed(2)} ${(circumference - dash).toFixed(2)}"
          stroke-dashoffset="${(-offset).toFixed(2)}"
          transform="rotate(-90 80 80)"
        >
          <title>${escapeHtml(d.label)}: ${d.value} (${Math.round(frac * 100)}%)</title>
        </circle>
      `;
      offset += dash;
      return seg;
    })
    .join("");

  const legend = items
    .map((d) => {
      const color = PALETTE[d.label] || "#00e5ff";
      return `
        <div class="legend-item">
          <span class="legend-swatch" style="background:${color}"></span>
          <span>${escapeHtml(d.label)}</span>
          <strong style="margin-left:auto" class="mono">${d.value}</strong>
        </div>
      `;
    })
    .join("");

  container.innerHTML = `
    <div class="donut-layout">
      <svg width="160" height="160" viewBox="0 0 160 160" role="img" aria-label="Distribution Chart">
        <circle cx="80" cy="80" r="${radius}" fill="transparent" stroke="#1e293b" stroke-width="20" />
        ${segments}
        <text x="80" y="76" text-anchor="middle" fill="#f8fafc" font-size="22" font-weight="800" font-family="Outfit, sans-serif">${total}</text>
        <text x="80" y="95" text-anchor="middle" fill="#94a3b8" font-size="11">TOTAL</text>
      </svg>
      <div class="chart-legend" style="min-width:140px">${legend}</div>
    </div>
  `;
}

export function renderHorizontalBarChart(container, items, colorFn) {
  if (!container) return;
  const maxVal = Math.max(1, ...items.map((d) => d.value ?? d.count ?? 0));
  container.innerHTML = `
    <div class="hbar-list">
      ${items
        .map((d, idx) => {
          const val = d.value ?? d.count ?? 0;
          const label = d.label ?? d.category ?? "";
          const pct = Math.round((val / maxVal) * 100);
          const color = colorFn ? colorFn(label, idx) : "#00e5ff";
          return `
            <div class="hbar-row" title="${escapeHtml(label)}: ${val}">
              <div class="hbar-meta">
                <span>${escapeHtml(label)}</span>
                <strong class="mono">${val}</strong>
              </div>
              <div class="hbar-track">
                <div class="hbar-fill" style="width:${pct}%; background:${color};"></div>
              </div>
            </div>
          `;
        })
        .join("")}
    </div>
  `;
}

export function renderTimeSeriesChart(container, points) {
  if (!container) return;
  if (!points || points.length === 0) {
    container.innerHTML = `<div class="card-subtitle">No timeline events recorded yet.</div>`;
    return;
  }

  const width = 520;
  const height = 190;
  const padX = 36;
  const padY = 24;
  const plotW = width - padX * 2;
  const plotH = height - padY * 2;

  const maxY = Math.max(1, ...points.map((p) => Math.max(p.total_events || 0, p.phishing_alerts || 0)));
  const stepX = points.length > 1 ? plotW / (points.length - 1) : 0;

  const toCoord = (idx, val) => {
    const x = points.length === 1 ? padX + plotW / 2 : padX + idx * stepX;
    const y = padY + plotH - (val / maxY) * plotH;
    return [x, y];
  };

  const totalLine = points
    .map((p, i) => toCoord(i, p.total_events || 0).join(","))
    .join(" ");
  const alertLine = points
    .map((p, i) => toCoord(i, p.phishing_alerts || 0).join(","))
    .join(" ");

  const dots = points
    .map((p, i) => {
      const [tx, ty] = toCoord(i, p.total_events || 0);
      const [ax, ay] = toCoord(i, p.phishing_alerts || 0);
      return `
        <circle cx="${tx}" cy="${ty}" r="4" fill="#00e5ff">
          <title>${escapeHtml(p.label)} — Total Events: ${p.total_events}</title>
        </circle>
        <circle cx="${ax}" cy="${ay}" r="4" fill="#ef4444">
          <title>${escapeHtml(p.label)} — Phishing Alerts: ${p.phishing_alerts}</title>
        </circle>
      `;
    })
    .join("");

  const xLabels = points
    .map((p, i) => {
      if (points.length > 5 && i !== 0 && i !== points.length - 1 && i % 2 !== 0) return "";
      const [x] = toCoord(i, 0);
      const short = String(p.label).slice(-5);
      return `<text x="${x}" y="${height - 4}" text-anchor="middle" fill="#64748b" font-size="10">${escapeHtml(short)}</text>`;
    })
    .join("");

  container.innerHTML = `
    <svg viewBox="0 0 ${width} ${height}" style="width:100%; height:auto;" role="img" aria-label="Phishing Events Over Time">
      <line x1="${padX}" y1="${padY}" x2="${padX}" y2="${padY + plotH}" stroke="#1e293b" />
      <line x1="${padX}" y1="${padY + plotH}" x2="${padX + plotW}" y2="${padY + plotH}" stroke="#1e293b" />
      <text x="${padX - 8}" y="${padY + 4}" text-anchor="end" fill="#64748b" font-size="10">${maxY}</text>
      <text x="${padX - 8}" y="${padY + plotH}" text-anchor="end" fill="#64748b" font-size="10">0</text>
      ${points.length > 1 ? `<polyline fill="none" stroke="#00e5ff" stroke-width="2.5" points="${totalLine}" />` : ""}
      ${points.length > 1 ? `<polyline fill="none" stroke="#ef4444" stroke-width="2.5" points="${alertLine}" />` : ""}
      ${dots}
      ${xLabels}
    </svg>
    <div style="display:flex; gap:1rem; font-size:0.76rem; color:var(--text-secondary); margin-top:0.35rem;">
      <span class="legend-item"><span class="legend-swatch" style="background:#00e5ff"></span>Total Events</span>
      <span class="legend-item"><span class="legend-swatch" style="background:#ef4444"></span>Phishing Alerts</span>
    </div>
  `;
}
