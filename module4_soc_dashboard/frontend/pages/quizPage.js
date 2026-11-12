/**
 * Interactive Phishing-Awareness Quiz Page (12 Questions, Immediate Feedback & Scoring).
 */
import { apiClient } from "../services/apiClient.js";
import { escapeHtml, showToast } from "../components/utils.js";

const quizState = {
  questions: [],
  passingPct: 75,
  selected: {},         // question_id -> optionIndex
  checkedFeedback: {},  // question_id -> { is_correct, correct_index, explanation }
  finalResult: null,
};

export async function renderQuizPage(container) {
  if (quizState.questions.length === 0) {
    container.innerHTML = `<div class="card"><div class="card-subtitle">Loading quiz assessment...</div></div>`;
    try {
      const data = await apiClient.getTrainingQuiz();
      quizState.questions = data.questions || [];
      quizState.passingPct = data.passing_threshold_pct ?? 75;
    } catch (err) {
      container.innerHTML = `<div class="card"><div class="badge badge-critical">${escapeHtml(err.message)}</div></div>`;
      return;
    }
  }

  paintQuiz(container);
}

function paintQuiz(container) {
  const total = quizState.questions.length;
  const answeredCount = Object.keys(quizState.selected).length;
  const result = quizState.finalResult;

  container.innerHTML = `
    <div class="card">
      <div class="card-header">
        <div>
          <div class="card-title">Interactive AiTM Phishing-Awareness Quiz (${total} Questions)</div>
          <div class="card-subtitle">Select an answer for immediate feedback, then submit for final certification scoring (Pass ≥ ${quizState.passingPct}%)</div>
        </div>
        <div class="toolbar">
          <span class="badge badge-info">Answered: ${answeredCount} / ${total}</span>
          <button id="restartQuizBtn" class="btn btn-secondary btn-sm">↺ Restart Quiz</button>
        </div>
      </div>

      ${
        result
          ? `
        <div class="card" style="background:var(--bg-input); border-color:${result.passed ? "var(--emerald)" : "var(--crimson)"}; margin-bottom:1.25rem;">
          <div style="display:flex; justify-content:space-between; align-items:center; gap:1rem; flex-wrap:wrap;">
            <div>
              <span class="badge ${result.passed ? "badge-low" : "badge-critical"}">
                ${result.passed ? "CERTIFICATION PASSED" : "NEEDS REVIEW"}
              </span>
              <h3 style="font-family:Outfit, sans-serif; font-size:1.35rem; margin-top:0.45rem;">
                Final Score: ${result.correct_answers} / ${result.total_questions} (${result.score_percentage}%)
              </h3>
              <p style="font-size:0.86rem; color:var(--text-secondary); margin-top:0.25rem;">
                ${escapeHtml(result.status_message)}
              </p>
            </div>
            <button id="restartQuizBannerBtn" class="btn btn-primary">↺ Retake Quiz</button>
          </div>
        </div>`
          : ""
      }

      <div id="quizQuestionsList">
        ${quizState.questions
          .map((q, qIdx) => {
            const chosen = quizState.selected[q.question_id];
            const fb = quizState.checkedFeedback[q.question_id];
            return `
          <div class="quiz-question-card" data-qid="${escapeHtml(q.question_id)}">
            <div style="display:flex; justify-content:space-between; align-items:center; gap:0.5rem;">
              <span class="mono" style="color:var(--cyan); font-weight:700;">Question ${qIdx + 1} of ${total} (${escapeHtml(q.question_id)})</span>
              ${
                fb
                  ? `<span class="badge ${fb.is_correct ? "badge-low" : "badge-critical"}">${fb.is_correct ? "✓ Correct" : "✗ Incorrect"}</span>`
                  : ""
              }
            </div>
            <div style="font-weight:700; font-size:0.95rem; margin:0.5rem 0 0.7rem;">${escapeHtml(q.question)}</div>

            <div>
              ${q.options
                .map((opt, oIdx) => {
                  let cls = "quiz-option-btn";
                  if (fb) {
                    if (oIdx === fb.correct_index) cls += " correct";
                    else if (oIdx === chosen && !fb.is_correct) cls += " incorrect";
                  } else if (chosen === oIdx) {
                    cls += " selected";
                  }
                  return `
                <button
                  type="button"
                  class="${cls}"
                  data-qid="${escapeHtml(q.question_id)}"
                  data-oidx="${oIdx}"
                  ${result ? "disabled" : ""}
                >
                  <strong class="mono">${String.fromCharCode(65 + oIdx)}.</strong>
                  <span>${escapeHtml(opt)}</span>
                </button>`;
                })
                .join("")}
            </div>

            ${
              fb
                ? `
              <div class="quiz-feedback-box" style="border-left-color:${fb.is_correct ? "var(--emerald)" : "var(--crimson)"};">
                <strong>${fb.is_correct ? "Correct!" : `Incorrect — Correct option is ${String.fromCharCode(65 + fb.correct_index)}.`}</strong>
                <div style="margin-top:0.25rem; color:var(--text-secondary);">${escapeHtml(fb.explanation)}</div>
              </div>`
                : ""
            }
          </div>`;
          })
          .join("")}
      </div>

      <div style="display:flex; justify-content:space-between; align-items:center; gap:1rem; flex-wrap:wrap; margin-top:1rem;">
        <span style="font-size:0.82rem; color:var(--text-secondary);">
          ${answeredCount < total ? `Answer all ${total} questions for a full score, or submit anytime.` : "All questions answered — ready to calculate final score."}
        </span>
        <div class="toolbar">
          <button id="submitQuizBtn" class="btn btn-success" ${result ? "disabled" : ""}>🏆 Calculate Final Score</button>
        </div>
      </div>
    </div>
  `;

  // Immediate check on option click
  container.querySelectorAll(".quiz-option-btn").forEach((btn) => {
    btn.addEventListener("click", async () => {
      if (quizState.finalResult) return;
      const qid = btn.dataset.qid;
      const oIdx = Number(btn.dataset.oidx);
      quizState.selected[qid] = oIdx;
      try {
        const fb = await apiClient.checkQuizQuestion(qid, oIdx);
        quizState.checkedFeedback[qid] = fb;
      } catch (err) {
        showToast(`Check error: ${err.message}`);
      }
      paintQuiz(container);
    });
  });

  const handleRestart = () => {
    quizState.selected = {};
    quizState.checkedFeedback = {};
    quizState.finalResult = null;
    showToast("Quiz restarted.");
    paintQuiz(container);
  };

  document.getElementById("restartQuizBtn")?.addEventListener("click", handleRestart);
  document.getElementById("restartQuizBannerBtn")?.addEventListener("click", handleRestart);

  document.getElementById("submitQuizBtn")?.addEventListener("click", async () => {
    try {
      const res = await apiClient.submitQuiz(quizState.selected);
      quizState.finalResult = res;
      (res.feedback || []).forEach((fb) => {
        quizState.checkedFeedback[fb.question_id] = fb;
      });
      showToast(`Final Score: ${res.score_percentage}% (${res.correct_answers}/${res.total_questions})`);
      paintQuiz(container);
      container.scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (err) {
      showToast(`Failed to grade quiz: ${err.message}`);
    }
  });
}
