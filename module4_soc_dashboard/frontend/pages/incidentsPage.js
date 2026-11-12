/**
 * Incident Management & Triage Page.
 */
import { apiClient } from "../services/apiClient.js";
import { renderIncidentDetailHtml } from "../components/incidentDetail.js";
import {
  escapeHtml,
  severityBadgeClass,
  showToast,
  statusBadgeClass,
} from "../components/utils.js";

const state = {
  search: "",
  severity: "All",
  status: "All",
  incidents: [],
  selectedId: null,
};

export async function renderIncidentsPage(container, onGlobalRefresh) {
  container.innerHTML = `
    <div class="card">
      <div class="card-header">
        <div>
          <div class="card-title">Incident Management &amp; Response</div>
          <div class="card-subtitle">Search, filter, investigate Module 2 signals, update triage status, and revoke compromised sessions</div>
        </div>
        <div class="toolbar">
          <input id="incSearch" class="input" type="search" placeholder="Search incident, session, user..." value="${escapeHtml(state.search)}" />
          <select id="incSeverityFilter" class="select">
            ${["All", "Critical", "High", "Medium", "Low"]
              .map((s) => `<option value="${s}" ${state.severity === s ? "selected" : ""}>Severity: ${s}</option>`)
              .join("")}
          </select>
          <select id="incStatusFilter" class="select">
            ${["All", "Open", "Investigating", "Contained", "Resolved"]
              .map((st) => `<option value="${st}" ${state.status === st ? "selected" : ""}>Status: ${st}</option>`)
              .join("")}
          </select>
        </div>
      </div>

      <div class="incident-split">
        <div id="incidentQueueList" class="incident-list">
          <div class="card-subtitle">Loading incidents...</div>
        </div>
        <div id="incidentDetailContainer" class="card" style="background:var(--bg-surface-alt);">
          <div class="card-subtitle">Select an incident from the queue to view full forensic details.</div>
        </div>
      </div>
    </div>
  `;

  document.getElementById("incSearch")?.addEventListener("input", (e) => {
    state.search = e.target.value;
    paintIncidentQueue(onGlobalRefresh);
  });
  document.getElementById("incSeverityFilter")?.addEventListener("change", (e) => {
    state.severity = e.target.value;
    paintIncidentQueue(onGlobalRefresh);
  });
  document.getElementById("incStatusFilter")?.addEventListener("change", (e) => {
    state.status = e.target.value;
    paintIncidentQueue(onGlobalRefresh);
  });

  try {
    const res = await apiClient.getIncidents();
    state.incidents = res.items || [];
    if (!state.selectedId && state.incidents.length > 0) {
      state.selectedId = state.incidents[0].incident_id;
    }
    paintIncidentQueue(onGlobalRefresh);
    if (state.selectedId) {
      await loadIncidentDetail(state.selectedId, onGlobalRefresh);
    }
  } catch (err) {
    showToast(`Failed to load incidents: ${err.message}`);
  }
}

function paintIncidentQueue(onGlobalRefresh) {
  const listEl = document.getElementById("incidentQueueList");
  if (!listEl) return;

  const q = state.search.trim().toLowerCase();
  const filtered = state.incidents.filter((inc) => {
    if (state.severity !== "All" && String(inc.severity).toLowerCase() !== state.severity.toLowerCase()) return false;
    if (state.status !== "All" && String(inc.status).toLowerCase() !== state.status.toLowerCase()) return false;
    if (q) {
      return (
        String(inc.incident_id).toLowerCase().includes(q) ||
        String(inc.session_id).toLowerCase().includes(q) ||
        String(inc.title).toLowerCase().includes(q) ||
        String(inc.user_alias).toLowerCase().includes(q)
      );
    }
    return true;
  });

  if (filtered.length === 0) {
    listEl.innerHTML = `<div class="card-subtitle">No incidents match the current filters.</div>`;
    return;
  }

  listEl.innerHTML = filtered
    .map(
      (inc) => `
    <div class="incident-card-item ${state.selectedId === inc.incident_id ? "selected" : ""}" data-id="${escapeHtml(inc.incident_id)}">
      <div style="display:flex; justify-content:space-between; align-items:center; gap:0.5rem;">
        <span class="mono" style="color:var(--cyan); font-weight:700;">${escapeHtml(inc.incident_id)}</span>
        <span class="badge ${severityBadgeClass(inc.severity)}">${escapeHtml(inc.severity)}</span>
      </div>
      <div style="font-weight:700; font-size:0.86rem; margin-top:0.35rem;">${escapeHtml(inc.title)}</div>
      <div style="display:flex; justify-content:space-between; align-items:center; margin-top:0.45rem; font-size:0.75rem; color:var(--text-secondary);">
        <span>${escapeHtml(inc.user_alias)} • Score: <strong>${inc.risk_score}</strong></span>
        <span class="badge ${statusBadgeClass(inc.status)}">${escapeHtml(inc.status)}</span>
      </div>
    </div>
  `
    )
    .join("");

  listEl.querySelectorAll(".incident-card-item").forEach((card) => {
    card.addEventListener("click", () => {
      state.selectedId = card.dataset.id;
      paintIncidentQueue(onGlobalRefresh);
      loadIncidentDetail(state.selectedId, onGlobalRefresh);
    });
  });
}

async function loadIncidentDetail(incidentId, onGlobalRefresh) {
  const detailEl = document.getElementById("incidentDetailContainer");
  if (!detailEl) return;

  try {
    const inc = await apiClient.getIncidentDetails(incidentId);
    detailEl.innerHTML = renderIncidentDetailHtml(inc);

    detailEl.querySelectorAll(".inc-status-btn").forEach((btn) => {
      btn.addEventListener("click", async () => {
        try {
          await apiClient.updateIncidentStatus(btn.dataset.id, btn.dataset.status);
          showToast(`Incident ${btn.dataset.id} status updated to ${btn.dataset.status}`);
          const refreshed = await apiClient.getIncidents();
          state.incidents = refreshed.items || [];
          paintIncidentQueue(onGlobalRefresh);
          await loadIncidentDetail(incidentId, onGlobalRefresh);
          if (onGlobalRefresh) onGlobalRefresh({ skipPageRender: true });
        } catch (err) {
          showToast(`Update failed: ${err.message}`);
        }
      });
    });

    detailEl.querySelectorAll(".inc-revoke-btn").forEach((btn) => {
      btn.addEventListener("click", async () => {
        try {
          const res = await apiClient.revokeSession(btn.dataset.session);
          showToast(res.message || `Session ${btn.dataset.session} revoked`);
          const refreshed = await apiClient.getIncidents();
          state.incidents = refreshed.items || [];
          paintIncidentQueue(onGlobalRefresh);
          await loadIncidentDetail(incidentId, onGlobalRefresh);
          if (onGlobalRefresh) onGlobalRefresh({ skipPageRender: true });
        } catch (err) {
          showToast(`Revocation failed: ${err.message}`);
        }
      });
    });
  } catch (err) {
    detailEl.innerHTML = `<div class="badge badge-critical">${escapeHtml(err.message)}</div>`;
  }
}
