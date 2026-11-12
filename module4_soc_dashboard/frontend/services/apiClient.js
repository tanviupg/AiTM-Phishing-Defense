/**
 * Module 4 API Client wrapping `/api/m4/*` endpoints.
 * Keeps UI components cleanly decoupled from transport details.
 */

async function request(path, options = {}) {
  const res = await fetch(path, {
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
    ...options,
  });

  if (!res.ok) {
    let message = `HTTP ${res.status}`;
    try {
      const errData = await res.json();
      if (errData && errData.detail) message = errData.detail;
    } catch (_) {
      // ignore non-json error bodies
    }
    throw new Error(message);
  }

  return res.json();
}

export const apiClient = {
  getSystemStatus: () => request("/api/m4/system/status"),
  getDashboardOverview: () => request("/api/m4/dashboard/overview"),

  getEvents: ({ severity = "", incidentStatus = "", search = "", limit = 100 } = {}) => {
    const params = new URLSearchParams();
    if (severity && severity !== "All") params.set("severity", severity);
    if (incidentStatus && incidentStatus !== "All") params.set("incident_status", incidentStatus);
    if (search) params.set("search", search);
    params.set("limit", String(limit));
    return request(`/api/m4/events?${params.toString()}`);
  },

  ingestModule1Events: () => request("/api/m4/pipeline/ingest-module1", { method: "POST" }),
  analyzeSyntheticEvent: (eventPayload) =>
    request("/api/m4/pipeline/analyze", {
      method: "POST",
      body: JSON.stringify(eventPayload),
    }),

  getLabScenarios: () => request("/api/m4/lab/scenarios"),
  runLabScenario: (scenarioId) =>
    request(`/api/m4/lab/scenarios/${encodeURIComponent(scenarioId)}/run`, { method: "POST" }),
  resetLab: () => request("/api/m4/lab/reset", { method: "POST" }),

  getIncidents: ({ severity = "", status = "", search = "" } = {}) => {
    const params = new URLSearchParams();
    if (severity && severity !== "All") params.set("severity", severity);
    if (status && status !== "All") params.set("status", status);
    if (search) params.set("search", search);
    return request(`/api/m4/incidents?${params.toString()}`);
  },

  getIncidentDetails: (incidentId) =>
    request(`/api/m4/incidents/${encodeURIComponent(incidentId)}`),

  updateIncidentStatus: (incidentId, status) =>
    request(`/api/m4/incidents/${encodeURIComponent(incidentId)}/status`, {
      method: "PATCH",
      body: JSON.stringify({ status }),
    }),

  getSessions: () => request("/api/m4/sessions"),
  revokeSession: (sessionId) =>
    request(`/api/m4/sessions/${encodeURIComponent(sessionId)}/revoke`, { method: "POST" }),
  testSessionAccess: (sessionId) =>
    request(`/api/m4/sessions/${encodeURIComponent(sessionId)}/test_access`, { method: "POST" }),

  getHardeningOverview: () => request("/api/m4/hardening/overview"),
  updateChecklistItem: (itemId, status, notes = null) =>
    request(`/api/m4/hardening/checklist/${encodeURIComponent(itemId)}`, {
      method: "PATCH",
      body: JSON.stringify({ status, notes }),
    }),

  getTrainingLessons: () => request("/api/m4/training/lessons"),
  getTrainingQuiz: () => request("/api/m4/training/quiz"),
  checkQuizQuestion: (questionId, selectedIndex) =>
    request("/api/m4/training/quiz/check", {
      method: "POST",
      body: JSON.stringify({ question_id: questionId, selected_index: selectedIndex }),
    }),
  submitQuiz: (answers) =>
    request("/api/m4/training/quiz/submit", {
      method: "POST",
      body: JSON.stringify({ answers }),
    }),
};
