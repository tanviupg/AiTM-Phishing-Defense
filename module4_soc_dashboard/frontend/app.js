/**
 * Module 4 SOC Dashboard & User-Training SPA Entrypoint.
 */
import { apiClient } from "./services/apiClient.js";
import { closeModal, escapeHtml, showToast } from "./components/utils.js";
import { renderDashboardPage } from "./pages/dashboardPage.js";
import { renderEventsPage } from "./pages/eventsPage.js";
import { renderIncidentsPage } from "./pages/incidentsPage.js";
import { renderHardeningPage } from "./pages/hardeningPage.js";
import { renderTrainingPage } from "./pages/trainingPage.js";
import { renderQuizPage } from "./pages/quizPage.js";

const ROUTES = {
  dashboard: {
    title: "SOC Command Dashboard",
    subtitle: "Real-time AiTM detection overview, threat analysis & analytics (Modules 1–3)",
    render: renderDashboardPage,
  },
  events: {
    title: "Security Event Monitoring",
    subtitle: "Searchable, sortable & filterable event telemetry with Module 2 risk scores",
    render: renderEventsPage,
  },
  incidents: {
    title: "Incident Management",
    subtitle: "Investigate alerts, inspect Formula R breakdowns & update triage statuses",
    render: renderIncidentsPage,
  },
  hardening: {
    title: "FIDO2 & Passkey Hardening",
    subtitle: "Module 3 authentication resistance matrix, session containment & checklist",
    render: renderHardeningPage,
  },
  training: {
    title: "User Awareness Training",
    subtitle: "9 interactive beginner-friendly lessons on AiTM phishing & passkey defense",
    render: renderTrainingPage,
  },
  quiz: {
    title: "Phishing-Awareness Quiz",
    subtitle: "12-question assessment with immediate feedback and certification scoring",
    render: renderQuizPage,
  },
};

function currentRoute() {
  const hash = (window.location.hash || "#dashboard").replace("#", "").trim().toLowerCase();
  return ROUTES[hash] ? hash : "dashboard";
}

async function updateSystemStatusUI() {
  const pill = document.getElementById("provenanceBadge");
  const textEl = document.getElementById("provenanceText");
  const banner = document.getElementById("fallbackWarningBanner");
  const connList = document.getElementById("moduleConnectivityList");

  try {
    const status = await apiClient.getSystemStatus();
    if (status.is_mock_data) {
      pill.className = "provenance-pill fallback";
      pill.querySelector(".dot").className = "dot dot-warn";
      textEl.textContent = "FALLBACK DEMO DATA";
      banner.classList.remove("hidden");
    } else {
      pill.className = "provenance-pill live";
      pill.querySelector(".dot").className = "dot dot-ok";
      textEl.textContent =
        status.integration_mode === "LIVE_MODULE3_API"
          ? "LIVE MODULE 3 API"
          : "LIVE PIPELINE (M1→M2→M3)";
      banner.classList.add("hidden");
    }

    const mods = status.modules || {};
    connList.innerHTML = [
      ["Module 1 (Events)", mods.module1_event_generator?.available],
      ["Module 2 (Detection)", mods.module2_detection_engine?.available],
      ["Module 3 (Hardening)", mods.module3_hardening_api?.available],
      ["Module 4 (Console)", mods.module4_soc_dashboard?.available],
    ]
      .map(
        ([label, ok]) =>
          `<li><span class="dot ${ok ? "dot-ok" : "dot-warn"}"></span><span>${escapeHtml(label)}</span></li>`
      )
      .join("");
  } catch (err) {
    pill.className = "provenance-pill fallback";
    textEl.textContent = "BACKEND UNREACHABLE";
  }
}

async function navigate({ skipPageRender = false } = {}) {
  const routeKey = currentRoute();
  const route = ROUTES[routeKey];

  document.querySelectorAll(".nav-link").forEach((link) => {
    link.classList.toggle("active", link.dataset.route === routeKey);
  });

  document.getElementById("pageHeading").textContent = route.title;
  document.getElementById("pageSubheading").textContent = route.subtitle;

  // Close mobile sidebar after selection
  document.getElementById("sidebar")?.classList.remove("open");
  document.getElementById("sidebarBackdrop")?.classList.remove("visible");

  await updateSystemStatusUI();

  if (!skipPageRender) {
    const container = document.getElementById("pageContainer");
    await route.render(container, (opts) => navigate(opts));
  }
}

function initShell() {
  const sidebar = document.getElementById("sidebar");
  const backdrop = document.getElementById("sidebarBackdrop");
  const mobileBtn = document.getElementById("mobileMenuBtn");

  mobileBtn?.addEventListener("click", () => {
    sidebar?.classList.toggle("open");
    backdrop?.classList.toggle("visible");
  });

  backdrop?.addEventListener("click", () => {
    sidebar?.classList.remove("open");
    backdrop?.classList.remove("visible");
  });

  document.getElementById("modalCloseBtn")?.addEventListener("click", closeModal);
  document.getElementById("modalOverlay")?.addEventListener("click", (e) => {
    if (e.target.id === "modalOverlay") closeModal();
  });

  document.getElementById("globalRefreshBtn")?.addEventListener("click", () => {
    showToast("Refreshing telemetry...");
    navigate();
  });

  window.addEventListener("hashchange", () => navigate());
  navigate();
}

window.addEventListener("DOMContentLoaded", initShell);
