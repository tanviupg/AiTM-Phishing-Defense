/**
 * Shared UI utilities for Module 4 SOC Dashboard.
 */

export function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export function formatTimestamp(ts) {
  if (!ts) return "—";
  const str = String(ts);
  return str.length >= 19 ? str.slice(0, 19).replace("T", " ") + " UTC" : str;
}

export function severityBadgeClass(severity) {
  const s = String(severity || "Low").toLowerCase();
  if (s === "critical") return "badge-critical";
  if (s === "high") return "badge-high";
  if (s === "medium") return "badge-medium";
  return "badge-low";
}

export function statusBadgeClass(status) {
  const s = String(status || "Open").toLowerCase();
  if (s === "resolved" || s === "monitored") return "badge-low";
  if (s === "investigating") return "badge-medium";
  if (s === "contained") return "badge-purple";
  return "badge-critical";
}

export function scoreColor(score) {
  const num = Number(score || 0);
  if (num >= 80) return "var(--crimson)";
  if (num >= 60) return "var(--orange)";
  if (num >= 30) return "var(--amber)";
  return "var(--emerald)";
}

export function showToast(message, durationMs = 3200) {
  const container = document.getElementById("toastContainer");
  if (!container) return;
  const el = document.createElement("div");
  el.className = "toast";
  el.textContent = message;
  container.appendChild(el);
  setTimeout(() => {
    el.remove();
  }, durationMs);
}

export function openModal(title, htmlContent) {
  const overlay = document.getElementById("modalOverlay");
  const titleEl = document.getElementById("modalTitle");
  const bodyEl = document.getElementById("modalBody");
  if (!overlay || !titleEl || !bodyEl) return;
  titleEl.textContent = title;
  bodyEl.innerHTML = htmlContent;
  overlay.classList.remove("hidden");
}

export function closeModal() {
  const overlay = document.getElementById("modalOverlay");
  if (overlay) overlay.classList.add("hidden");
}
