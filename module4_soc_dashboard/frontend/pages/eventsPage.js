/**
 * Security Event Monitoring Page (Search, Multi-Filter & Column Sorting).
 */
import { apiClient } from "../services/apiClient.js";
import {
  escapeHtml,
  formatTimestamp,
  openModal,
  scoreColor,
  severityBadgeClass,
  showToast,
  statusBadgeClass,
} from "../components/utils.js";

const state = {
  search: "",
  severity: "All",
  incidentStatus: "All",
  sortField: "timestamp",
  sortDir: "desc",
  events: [],
};

export async function renderEventsPage(container) {
  container.innerHTML = `
    <div class="card">
      <div class="card-header">
        <div>
          <div class="card-title">Security Event Monitoring Stream</div>
          <div class="card-subtitle">Normalized authentication telemetry enriched with Module 2 risk scores &amp; Module 3 incident states</div>
        </div>
        <div class="toolbar">
          <input id="evSearch" class="input" type="search" placeholder="Search Event ID, Session, IP, reason..." value="${escapeHtml(state.search)}" />
          <select id="evSeverity" class="select" aria-label="Filter by severity">
            ${["All", "Critical", "High", "Medium", "Low"]
              .map((s) => `<option value="${s}" ${state.severity === s ? "selected" : ""}>Severity: ${s}</option>`)
              .join("")}
          </select>
          <select id="evStatus" class="select" aria-label="Filter by incident status">
            ${["All", "Open", "Investigating", "Contained", "Resolved", "Monitored"]
              .map((st) => `<option value="${st}" ${state.incidentStatus === st ? "selected" : ""}>Status: ${st}</option>`)
              .join("")}
          </select>
        </div>
      </div>

      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th class="sortable" data-sort="event_id">Event ID ${sortArrow("event_id")}</th>
              <th class="sortable" data-sort="timestamp">Timestamp ${sortArrow("timestamp")}</th>
              <th class="sortable" data-sort="session_id">Session ID ${sortArrow("session_id")}</th>
              <th class="sortable" data-sort="risk_score">Risk Score ${sortArrow("risk_score")}</th>
              <th class="sortable" data-sort="severity">Threat Severity ${sortArrow("severity")}</th>
              <th>Detection Reason</th>
              <th class="sortable" data-sort="incident_status">Incident Status ${sortArrow("incident_status")}</th>
              <th>Telemetry</th>
            </tr>
          </thead>
          <tbody id="eventsTbody">
            <tr><td colspan="8" style="color:var(--text-muted)">Loading security events...</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  `;

  await loadAndPaintEvents(container);

  document.getElementById("evSearch")?.addEventListener("input", (e) => {
    state.search = e.target.value;
    paintTableRows();
  });
  document.getElementById("evSeverity")?.addEventListener("change", (e) => {
    state.severity = e.target.value;
    paintTableRows();
  });
  document.getElementById("evStatus")?.addEventListener("change", (e) => {
    state.incidentStatus = e.target.value;
    paintTableRows();
  });

  container.querySelectorAll("th.sortable").forEach((th) => {
    th.addEventListener("click", () => {
      const field = th.dataset.sort;
      if (state.sortField === field) {
        state.sortDir = state.sortDir === "asc" ? "desc" : "asc";
      } else {
        state.sortField = field;
        state.sortDir = "desc";
      }
      renderEventsPage(container);
    });
  });
}

function sortArrow(field) {
  if (state.sortField !== field) return "⇅";
  return state.sortDir === "asc" ? "▲" : "▼";
}

async function loadAndPaintEvents() {
  try {
    const res = await apiClient.getEvents({ limit: 200 });
    state.events = res.items || [];
    paintTableRows();
  } catch (err) {
    showToast(`Failed to load events: ${err.message}`);
  }
}

function paintTableRows() {
  const tbody = document.getElementById("eventsTbody");
  if (!tbody) return;

  const q = state.search.trim().toLowerCase();
  let rows = state.events.filter((e) => {
    if (state.severity !== "All" && String(e.severity).toLowerCase() !== state.severity.toLowerCase()) {
      return false;
    }
    if (
      state.incidentStatus !== "All" &&
      String(e.incident_status).toLowerCase() !== state.incidentStatus.toLowerCase()
    ) {
      return false;
    }
    if (q) {
      return (
        String(e.event_id).toLowerCase().includes(q) ||
        String(e.session_id).toLowerCase().includes(q) ||
        String(e.user_alias).toLowerCase().includes(q) ||
        String(e.source_ip).toLowerCase().includes(q) ||
        String(e.detection_reason).toLowerCase().includes(q)
      );
    }
    return true;
  });

  const dir = state.sortDir === "asc" ? 1 : -1;
  rows.sort((a, b) => {
    const va = a[state.sortField];
    const vb = b[state.sortField];
    if (typeof va === "number" && typeof vb === "number") return (va - vb) * dir;
    return String(va ?? "").localeCompare(String(vb ?? "")) * dir;
  });

  if (rows.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" style="color:var(--text-muted)">No matching security events found.</td></tr>`;
    return;
  }

  tbody.innerHTML = rows
    .map(
      (ev) => `
    <tr>
      <td class="mono" style="color:var(--cyan); font-weight:700;">${escapeHtml(ev.event_id)}</td>
      <td class="mono" style="color:var(--text-secondary);">${escapeHtml(formatTimestamp(ev.timestamp))}</td>
      <td class="mono">${escapeHtml(ev.session_id)}</td>
      <td>
        <div class="score-bar-wrap">
          <div class="score-bar-track">
            <div class="score-bar-fill" style="width:${Math.min(100, ev.risk_score)}%; background:${scoreColor(ev.risk_score)};"></div>
          </div>
          <strong class="mono">${ev.risk_score}</strong>
        </div>
      </td>
      <td><span class="badge ${severityBadgeClass(ev.severity)}">${escapeHtml(ev.severity)}</span></td>
      <td style="max-width:340px; font-size:0.81rem; color:var(--text-secondary);">${escapeHtml(ev.detection_reason)}</td>
      <td><span class="badge ${statusBadgeClass(ev.incident_status)}">${escapeHtml(ev.incident_status)}</span></td>
      <td><button class="btn btn-secondary btn-sm inspect-ev-btn" data-id="${escapeHtml(ev.event_id)}">{ } Inspect</button></td>
    </tr>
  `
    )
    .join("");

  tbody.querySelectorAll(".inspect-ev-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const ev = state.events.find((x) => x.event_id === btn.dataset.id);
      if (ev) {
        openModal(
          `Event Telemetry — ${ev.event_id}`,
          `<pre class="json-pre">${escapeHtml(JSON.stringify(ev, null, 2))}</pre>`
        );
      }
    });
  });
}
