/**
 * Reusable Incident Details & Investigation Renderer.
 */
import { escapeHtml, formatTimestamp, severityBadgeClass, statusBadgeClass, scoreColor } from "./utils.js";

export function renderIncidentDetailHtml(inc) {
  const fb = inc.formula_breakdown || {};
  const vars = fb.variables || {};
  const contrib = fb.contributions || {};
  const signals = inc.signals || {};
  const timeline = inc.timeline || [];
  const recs = inc.recommendations || [];

  return `
    <div style="display:flex; flex-direction:column; gap:1rem;">
      <div style="display:flex; justify-content:space-between; align-items:flex-start; gap:1rem; flex-wrap:wrap;">
        <div>
          <div class="mono" style="color:var(--cyan); font-weight:700;">${escapeHtml(inc.incident_id)}</div>
          <h3 style="font-family:Outfit, sans-serif; font-size:1.15rem; margin-top:0.15rem;">${escapeHtml(inc.title)}</h3>
          <div style="font-size:0.82rem; color:var(--text-secondary); margin-top:0.25rem;">
            User: <strong>${escapeHtml(inc.user_alias)}</strong> • Session: <span class="mono">${escapeHtml(inc.session_id)}</span> (${escapeHtml(inc.session_current_status || "unknown")})
          </div>
        </div>
        <div style="display:flex; gap:0.5rem; align-items:center; flex-wrap:wrap;">
          <span class="badge ${severityBadgeClass(inc.severity)}">${escapeHtml(inc.severity)}</span>
          <span class="badge ${statusBadgeClass(inc.status)}">${escapeHtml(inc.status)}</span>
          <span class="badge badge-info" style="color:${scoreColor(inc.risk_score)}">Score: ${inc.risk_score}/100</span>
        </div>
      </div>

      ${inc.is_mock_data ? `<div class="badge badge-medium">Synthetic Fallback Record (Not Live Pipeline Output)</div>` : ""}

      <div class="card" style="background:var(--bg-input); padding:0.9rem;">
        <div style="font-size:0.78rem; font-weight:700; color:var(--cyan); margin-bottom:0.5rem;">
          Explainable Risk Formula (Module 2/3): ${escapeHtml(fb.formula || "R = 30D + 20C + 25S + 15E + 10A")}
        </div>
        <div class="formula-chips">
          <div class="formula-chip ${vars.D ? "active" : ""}">D (Domain): +${contrib.D || 0}</div>
          <div class="formula-chip ${vars.C ? "active" : ""}">C (TLS/Cert): +${contrib.C || 0}</div>
          <div class="formula-chip ${vars.S ? "active" : ""}">S (Replay): +${contrib.S || 0}</div>
          <div class="formula-chip ${vars.E ? "active" : ""}">E (Redirects): +${contrib.E || 0}</div>
          <div class="formula-chip ${vars.A ? "active" : ""}">A (Context): +${contrib.A || 0}</div>
        </div>
      </div>

      <div>
        <div style="font-size:0.82rem; font-weight:700; margin-bottom:0.45rem;">Active Threat Signals</div>
        <div style="display:flex; gap:0.45rem; flex-wrap:wrap;">
          ${Object.entries(signals)
            .map(([k, v]) => `<span class="badge ${v ? "badge-critical" : "badge-low"}">${escapeHtml(k)}: ${v ? "TRIGGERED" : "CLEAN"}</span>`)
            .join("") || `<span class="card-subtitle">No signal flags recorded.</span>`}
        </div>
      </div>

      <div>
        <div style="font-size:0.82rem; font-weight:700; margin-bottom:0.45rem;">Investigation Timeline</div>
        ${
          timeline.length === 0
            ? `<div class="card-subtitle">No timeline steps recorded.</div>`
            : `<div style="display:flex; flex-direction:column; gap:0.55rem;">
                ${timeline
                  .map(
                    (t, idx) => `
                  <div class="threat-reason-item">
                    <div style="display:flex; justify-content:space-between; font-size:0.74rem; color:var(--text-muted);">
                      <strong>Step ${idx + 1}: ${escapeHtml(t.stage)}</strong>
                      <span class="mono">${escapeHtml(formatTimestamp(t.timestamp))}</span>
                    </div>
                    <div style="margin-top:0.2rem;">${escapeHtml(t.details)}</div>
                    ${
                      Array.isArray(t.redirect_chain) && t.redirect_chain.length > 0
                        ? `<div class="hop-chain" style="margin-top:0.45rem;">
                            ${t.redirect_chain
                              .map((host) => `<span class="hop-pill ${host.includes("proxy") || host.includes("invalid") ? "suspicious" : ""}">${escapeHtml(host)}</span>`)
                              .join(`<span style="color:var(--text-muted)">→</span>`)}
                          </div>`
                        : ""
                    }
                  </div>
                `
                  )
                  .join("")}
              </div>`
        }
      </div>

      <div>
        <div style="font-size:0.82rem; font-weight:700; margin-bottom:0.45rem;">Module 3 Defensive Recommendations</div>
        <ul style="padding-left:1.25rem; font-size:0.84rem; color:var(--text-secondary);">
          ${recs.map((r) => `<li>${escapeHtml(r)}</li>`).join("") || `<li>Continue routine monitoring</li>`}
        </ul>
      </div>

      <div style="display:flex; gap:0.6rem; flex-wrap:wrap; align-items:center; padding-top:0.5rem; border-top:1px solid var(--border);">
        <label style="font-size:0.8rem; color:var(--text-secondary);">Update Status:</label>
        <button class="btn btn-secondary btn-sm inc-status-btn" data-id="${escapeHtml(inc.incident_id)}" data-status="Open">Open</button>
        <button class="btn btn-secondary btn-sm inc-status-btn" data-id="${escapeHtml(inc.incident_id)}" data-status="Investigating">Investigating</button>
        <button class="btn btn-success btn-sm inc-status-btn" data-id="${escapeHtml(inc.incident_id)}" data-status="Resolved">Resolved</button>
        <button class="btn btn-danger btn-sm inc-revoke-btn" data-session="${escapeHtml(inc.session_id)}" data-id="${escapeHtml(inc.incident_id)}" style="margin-left:auto;">
          🔒 Revoke Session (M3)
        </button>
      </div>
    </div>
  `;
}
