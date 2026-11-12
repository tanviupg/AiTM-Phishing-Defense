/**
 * Interactive User-Training Module (9 Beginner-Friendly Lessons).
 */
import { apiClient } from "../services/apiClient.js";
import { escapeHtml, showToast } from "../components/utils.js";

const STORAGE_KEY = "aitm_m4_completed_lessons";

function getCompletedSet() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return new Set(raw ? JSON.parse(raw) : []);
  } catch (_) {
    return new Set();
  }
}

function saveCompletedSet(set) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(Array.from(set)));
  } catch (_) {
    // ignore storage errors
  }
}

let activeLessonIdx = 0;

export async function renderTrainingPage(container) {
  container.innerHTML = `<div class="card"><div class="card-subtitle">Loading training curriculum...</div></div>`;

  let data;
  try {
    data = await apiClient.getTrainingLessons();
  } catch (err) {
    container.innerHTML = `<div class="card"><div class="badge badge-critical">${escapeHtml(err.message)}</div></div>`;
    return;
  }

  const lessons = data.lessons || [];
  if (lessons.length === 0) {
    container.innerHTML = `<div class="card"><div class="card-subtitle">No training lessons found.</div></div>`;
    return;
  }

  if (activeLessonIdx >= lessons.length) activeLessonIdx = 0;

  function paint() {
    const completed = getCompletedSet();
    const lesson = lessons[activeLessonIdx];
    const isDone = completed.has(lesson.lesson_id);
    const pct = Math.round((completed.size / lessons.length) * 100);

    container.innerHTML = `
      <div class="card">
        <div class="card-header">
          <div>
            <div class="card-title">AiTM Phishing Defense Awareness Curriculum</div>
            <div class="card-subtitle">9 structured beginner-friendly lessons integrating Module 3 FIDO2 defense knowledge</div>
          </div>
          <div style="min-width:220px;">
            <div style="display:flex; justify-content:space-between; font-size:0.78rem; margin-bottom:0.3rem;">
              <span>Course Progress</span>
              <strong class="mono">${completed.size}/${lessons.length} (${pct}%)</strong>
            </div>
            <div class="hbar-track"><div class="hbar-fill" style="width:${pct}%; background:var(--emerald);"></div></div>
          </div>
        </div>

        <div class="training-layout">
          <!-- Topic List -->
          <div style="display:flex; flex-direction:column; gap:0.45rem;">
            ${lessons
              .map((l, idx) => {
                const done = completed.has(l.lesson_id);
                return `
              <button class="lesson-nav-item ${idx === activeLessonIdx ? "active" : ""}" data-idx="${idx}">
                <span style="font-size:0.83rem; font-weight:600;">${l.order}. ${escapeHtml(l.title)}</span>
                <span class="badge ${done ? "badge-low" : "badge-info"}">${done ? "✓" : `${l.duration_min}m`}</span>
              </button>`;
              })
              .join("")}
          </div>

          <!-- Active Lesson Content -->
          <article class="card" style="background:var(--bg-surface-alt);">
            <div style="display:flex; justify-content:space-between; align-items:flex-start; gap:0.75rem; flex-wrap:wrap;">
              <div>
                <div style="display:flex; gap:0.5rem; align-items:center; flex-wrap:wrap;">
                  <span class="badge badge-info">Lesson ${lesson.order} of ${lessons.length}</span>
                  <span class="badge badge-purple">${escapeHtml(lesson.category)}</span>
                  <span style="font-size:0.74rem; color:var(--text-muted);">${escapeHtml(lesson.source_module_ref)}</span>
                </div>
                <h2 style="font-family:Outfit, sans-serif; font-size:1.35rem; margin-top:0.5rem;">${escapeHtml(lesson.title)}</h2>
              </div>
              <button id="toggleLessonDoneBtn" class="btn ${isDone ? "btn-success" : "btn-secondary"} btn-sm">
                ${isDone ? "✓ Completed" : "Mark as Completed"}
              </button>
            </div>

            <div class="lesson-section">
              <h4>Simple Explanation</h4>
              <p style="font-size:0.9rem; color:var(--text-primary);">${escapeHtml(lesson.simple_explanation)}</p>
            </div>

            <div class="lesson-section">
              <h4>Practical Real-World / Lab Example</h4>
              <p style="font-size:0.88rem; color:var(--text-secondary);">${escapeHtml(lesson.practical_example)}</p>
            </div>

            <div class="grid-2" style="margin-top:0.2rem;">
              <div class="lesson-section">
                <h4 style="color:var(--amber);">Warning Signs</h4>
                <ul>
                  ${(lesson.warning_signs || []).map((w) => `<li>${escapeHtml(w)}</li>`).join("")}
                </ul>
              </div>
              <div class="lesson-section">
                <h4 style="color:var(--emerald);">Prevention Techniques</h4>
                <ul>
                  ${(lesson.prevention_techniques || []).map((p) => `<li>${escapeHtml(p)}</li>`).join("")}
                </ul>
              </div>
            </div>

            <div style="margin-top:0.9rem; padding:0.75rem 1rem; border-left:3px solid var(--emerald); background:var(--emerald-soft); border-radius:6px; font-size:0.84rem;">
              <strong>Key Security Tip:</strong> ${escapeHtml(lesson.module3_takeaway)}
            </div>

            <div style="display:flex; justify-content:space-between; margin-top:1.15rem; gap:0.75rem; flex-wrap:wrap;">
              <button id="prevLessonBtn" class="btn btn-secondary btn-sm" ${activeLessonIdx === 0 ? "disabled" : ""}>← Previous Lesson</button>
              <div class="toolbar">
                ${
                  activeLessonIdx < lessons.length - 1
                    ? `<button id="nextLessonBtn" class="btn btn-primary btn-sm">Next Lesson →</button>`
                    : `<a href="#quiz" class="btn btn-success btn-sm">Take Certification Quiz →</a>`
                }
              </div>
            </div>
          </article>
        </div>
      </div>
    `;

    container.querySelectorAll(".lesson-nav-item").forEach((btn) => {
      btn.addEventListener("click", () => {
        activeLessonIdx = Number(btn.dataset.idx);
        paint();
      });
    });

    document.getElementById("toggleLessonDoneBtn")?.addEventListener("click", () => {
      const set = getCompletedSet();
      if (set.has(lesson.lesson_id)) {
        set.delete(lesson.lesson_id);
      } else {
        set.add(lesson.lesson_id);
        showToast(`Lesson ${lesson.order} marked complete!`);
      }
      saveCompletedSet(set);
      paint();
    });

    document.getElementById("prevLessonBtn")?.addEventListener("click", () => {
      if (activeLessonIdx > 0) {
        activeLessonIdx--;
        paint();
      }
    });

    document.getElementById("nextLessonBtn")?.addEventListener("click", () => {
      const set = getCompletedSet();
      set.add(lesson.lesson_id);
      saveCompletedSet(set);
      if (activeLessonIdx < lessons.length - 1) {
        activeLessonIdx++;
        paint();
      }
    });
  }

  paint();
}
