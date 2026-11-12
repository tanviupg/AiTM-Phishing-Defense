/**
 * SOC Dashboard Overview, Threat Analysis & Interactive Analytics Page.
 */
import { apiClient } from "../services/apiClient.js";
import { renderDonutChart, renderHorizontalBarChart, renderTimeSeriesChart } from "../components/charts.js";
import { escapeHtml, severityBadgeClass, statusBadgeClass, showToast, openModal } from "../components/utils.js";
import { renderIncidentDetailHtml } from "../components/incidentDetail.js";

export async function renderDashboardPage(container, onGlobalRefresh) {
  container.innerHTML = `<div class="card"><div class="card-subtitle">Loading SOC telemetry...</div></div>`;

  let overview;
  let scenarios = [];
  try {
    [overview, scenarios] = await Promise.all([
      apiClient.getDashboardOverview(),
      apiClient.getLabScenarios().catch(() => []),
    ]);
  } catch (err) {
    container.innerHTML = `<div class="card"><div class="badge badge-critical">Error loading dashboard</div><p style="margin-top:0.5rem;">${escapeHtml(err.message)}</p></div>`;
    return;
  }

  const kpi = overview.overview;
  const threat = overview.threat_analysis;
  const charts = overview.charts;

  container.innerHTML = `
    <!-- 1. Overview KPI Cards -->
    <section class="kpi-grid" aria-label="SOC Overview Metrics">
      <div class="kpi-card">
        <div class="kpi-top"><span>Total Monitored Events</span><span>📡</span></div>
        <div class="kpi-value" style="color:var(--cyan)">${kpi.total_events}</div>
        <div class="kpi-foot">Module 1 -> Module 2 pipeline</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-top"><span>Total Phishing Alerts</span><span>⚠️</span></div>
        <div class="kpi-value" style="color:var(--crimson)">${kpi.total_phishing_alerts}</div>
        <div class="kpi-foot">Medium / High / Critical events</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-top"><span>High-Risk Incidents</span><span>🔴</span></div>
        <div class="kpi-value" style="color:var(--orange)">${kpi.high_risk_incidents}</div>
        <div class="kpi-foot">Score ≥ 60 or Critical</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-top"><span>Medium-Risk Incidents</span><span>🟡</span></div>
        <div class="kpi-value" style="color:var(--amber)">${kpi.medium_risk_incidents}</div>
        <div class="kpi-foot">Score 30–59 (Triage queue)</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-top"><span>Low-Risk Incidents</span><span>🟢</span></div>
        <div class="kpi-value" style="color:var(--emerald)">${kpi.low_risk_incidents}</div>
        <div class="kpi-foot">${kpi.low_risk_events} benign monitored events</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-top"><span>Suspicious Sessions</span><span>🔑</span></div>
        <div class="kpi-value" style="color:var(--purple)">${kpi.suspicious_sessions}</div>
        <div class="kpi-foot">${kpi.revoked_sessions} revoked / contained</div>
      </div>
    </section>

    <!-- Pipeline Integration Runner -->
    <section class="card">
      <div class="card-header">
        <div>
          <div class="card-title">Live Pipeline Integration Controls (Modules 1 → 2 → 3)</div>
          <div class="card-subtitle">Ingest Module 1 session events or execute Module 3 controlled detection scenarios</div>
        </div>
        <div class="toolbar">
          <button id="btnIngestM1" class="btn btn-secondary btn-sm">📥 Ingest Module 1 Events</button>
          <select id="labScenarioPicker" class="select">
            ${
              scenarios.length
                ? scenarios
                    .map((s) => `<option value="${escapeHtml(s.scenario_id)}">${escapeHtml(s.scenario_id)}: ${escapeHtml(s.title)} (${escapeHtml(s.expected_risk_level)})</option>`)
                    .join("")
                : `<option value="">Lab scenarios unavailable in fallback mode</option>`
            }
          </select>
          <button id="btnRunScenario" class="btn btn-primary btn-sm" ${scenarios.length ? "" : "disabled"}>⚡ Run Scenario</button>
          <button id="btnResetLab" class="btn btn-danger btn-sm">↺ Reset Baseline</button>
        </div>
      </div>
    </section>

    <!-- 3. Threat Analysis Indicators -->
    <section class="card">
      <div class="card-header">
        <div>
          <div class="card-title">Threat Detection Analysis (Module 2 Signals)</div>
          <div class="card-subtitle">Defensive indicators grouped by transport, redirect topology, session behavior, and simulated replay</div>
        </div>
      </div>
      <div class="threat-grid">
        ${renderThreatBox("TLS / Certificate Anomalies", "🔒", threat.tls_certificate_anomalies, "badge-critical")}
        ${renderThreatBox("Suspicious Redirect Chains", "🔀", threat.suspicious_redirect_chains, "badge-high")}
        ${renderThreatBox("Session-Related Anomalies", "🖥️", threat.session_anomalies, "badge-medium")}
        ${renderThreatBox("Token-Replay Indicators", "🎟️", threat.token_replay_indicators, "badge-purple")}
      </div>
    </section>

    <!-- 4. Analytics & Visualizations -->
    <section class="grid-2">
      <div class="card">
        <div class="card-header">
          <div>
            <div class="card-title">Threat Severity Distribution</div>
            <div class="card-subtitle">Breakdown across Critical, High, Medium, and Low events</div>
          </div>
        </div>
        <div id="chartSeverity" class="chart-box"></div>
      </div>

      <div class="card">
        <div class="card-header">
          <div>
            <div class="card-title">Risk-Score Distribution</div>
            <div class="card-subtitle">Module 2 &amp; Formula R score buckets (0–100)</div>
          </div>
        </div>
        <div id="chartRiskScore" class="chart-box"></div>
      </div>

      <div class="card">
        <div class="card-header">
          <div>
            <div class="card-title">Phishing Events Over Time</div>
            <div class="card-subtitle">Monitored authentication events vs. phishing alerts</div>
          </div>
        </div>
        <div id="chartTimeSeries" class="chart-box"></div>
      </div>

      <div class="card">
        <div class="card-header">
          <div>
            <div class="card-title">Detection Category Distribution</div>
            <div class="card-subtitle">Triggered indicators by detection subsystem</div>
          </div>
        </div>
        <div id="chartCategories" class="chart-box"></div>
      </div>
    </section>

    <section class="grid-2">
      <div class="card">
        <div class="card-header">
          <div>
            <div class="card-title">Incident Status Statistics</div>
            <div class="card-subtitle">Current SOC triage workflow distribution</div>
          </div>
        </div>
        <div id="chartIncidentStats" class="chart-box"></div>
      </div>

      <div class="card">
        <div class="card-header">
          <div>
            <div class="card-title">Recent Security Incidents</div>
            <div class="card-subtitle">Latest incidents flagged by the detection pipeline</div>
          </div>
          <a href="#incidents" class="btn btn-secondary btn-sm">View All →</a>
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Incident</th>
                <th>Severity</th>
                <th>Score</th>
                <th>Status</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              ${
                overview.recent_incidents.length === 0
                  ? `<tr><td colspan="5" style="color:var(--text-muted)">No incidents recorded yet.</td></tr>`
                  : overview.recent_incidents
                      .map(
                        (inc) => `
                <tr>
                  <td>
                    <div class="mono" style="color:var(--cyan); font-weight:700;">${escapeHtml(inc.incident_id)}</div>
                    <div style="font-size:0.76rem; color:var(--text-secondary);">${escapeHtml(inc.title)}</div>
                  </td>
                  <td><span class="badge ${severityBadgeClass(inc.severity)}">${escapeHtml(inc.severity)}</span></td>
                  <td class="mono"><strong>${inc.risk_score}/100</strong></td>
                  <td><span class="badge ${statusBadgeClass(inc.status)}">${escapeHtml(inc.status)}</span></td>
                  <td><button class="btn btn-secondary btn-sm quick-inc-btn" data-id="${escapeHtml(inc.incident_id)}">Inspect</button></td>
                </tr>`
                      )
                      .join("")
              }
            </tbody>
          </table>
        </div>
      </div>
    </section>
  `;

  // Render Charts
  renderDonutChart(document.getElementById("chartSeverity"), charts.severity_distribution, "No events");
  renderHorizontalBarChart(
    document.getElementById("chartRiskScore"),
    charts.risk_score_distribution,
    (label) => {
      if (label.startsWith("80")) return "#ef4444";
      if (label.startsWith("60")) return "#f97316";
      if (label.startsWith("30")) return "#f59e0b";
      return "#10b981";
    }
  );
  renderTimeSeriesChart(document.getElementById("chartTimeSeries"), charts.events_over_time);
  renderHorizontalBarChart(
    document.getElementById("chartCategories"),
    charts.detection_category_distribution,
    (_, idx) => ["#ef4444", "#f97316", "#8b5cf6", "#00e5ff"][idx % 4]
  );
  renderDonutChart(document.getElementById("chartIncidentStats"), charts.incident_statistics, "No incidents yet");

  // Bind Actions
  document.getElementById("btnIngestM1")?.addEventListener("click", async () => {
    try {
      const res = await apiClient.ingestModule1Events();
      showToast(`Ingested ${res.ingested_count} Module 1 event(s) through Module 2 & 3.`);
      onGlobalRefresh();
    } catch (err) {
      showToast(`Ingestion error: ${err.message}`);
    }
  });

  document.getElementById("btnRunScenario")?.addEventListener("click", async () => {
    const scenarioId = document.getElementById("labScenarioPicker")?.value;
    if (!scenarioId) return;
    try {
      const res = await apiClient.runLabScenario(scenarioId);
      showToast(
        `Executed ${scenarioId}: ${res.observed_outcome?.risk_level || "OK"} (Score ${res.formula_scoring?.score_out_of_100 ?? 0}/100)`
      );
      onGlobalRefresh();
    } catch (err) {
      showToast(`Scenario failed: ${err.message}`);
    }
  });

  document.getElementById("btnResetLab")?.addEventListener("click", async () => {
    try {
      await apiClient.resetLab();
      showToast("Lab baseline reset; re-ingesting clean baseline.");
      onGlobalRefresh();
    } catch (err) {
      showToast(`Reset failed: ${err.message}`);
    }
  });

  container.querySelectorAll(".quick-inc-btn").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const incId = btn.dataset.id;
      try {
        const inc = await apiClient.getIncidentDetails(incId);
        openModal(`Incident Investigation — ${inc.incident_id}`, renderIncidentDetailHtml(inc));
        bindModalIncidentActions(onGlobalRefresh);
      } catch (err) {
        showToast(`Failed to open incident: ${err.message}`);
      }
    });
  });
}

function renderThreatBox(title, icon, group, badgeCls) {
  const items = group?.items || [];
  return `
    <div class="threat-box">
      <div class="threat-box-head">
        <div style="font-weight:700; font-size:0.88rem;">${icon} ${escapeHtml(title)}</div>
        <span class="badge ${badgeCls} threat-count">${group?.count ?? 0}</span>
      </div>
      <div class="threat-reason-list">
        ${
          items.length === 0
            ? `<div style="color:var(--text-muted)">No active anomalies detected in this category.</div>`
            : items
                .slice(0, 3)
                .map(
                  (it) => `
              <div class="threat-reason-item">
                <div class="mono" style="color:var(--cyan); font-weight:600;">${escapeHtml(it.session_id)}</div>
                <div>${escapeHtml(it.reason)}</div>
              </div>`
                )
                .join("")
        }
      </div>
    </div>
  `;
}

export function bindModalIncidentActions(onRefresh) {
  document.querySelectorAll("#modalBody .inc-status-btn").forEach((btn) => {
    btn.addEventListener("click", async () => {
      try {
        await apiClient.updateIncidentStatus(btn.dataset.id, btn.dataset.status);
        showToast(`Incident ${btn.dataset.id} updated to ${btn.dataset.status}`);
        const inc = await apiClient.getIncidentDetails(btn.dataset.id);
        document.getElementById("modalBody").innerHTML = renderIncidentDetailHtml(inc);
        bindModalIncidentActions(onRefresh);
        if (onRefresh) onRefresh();
      } catch (err) {
        showToast(`Status update error: ${err.message}`);
      }
    });
  });

  document.querySelectorAll("#modalBody .inc-revoke-btn").forEach((btn) => {
    btn.addEventListener("click", async () => {
      try {
        const res = await apiClient.revokeSession(btn.dataset.session);
        showToast(res.message || `Session ${btn.dataset.session} revoked`);
        const inc = await apiClient.getIncidentDetails(btn.dataset.id);
        document.getElementById("modalBody").innerHTML = renderIncidentDetailHtml(inc);
        bindModalIncidentActions(onRefresh);
        if (onRefresh) onRefresh();
      } catch (err) {
        showToast(`Revocation failed: ${err.message}`);
      }
    });
  });
}
