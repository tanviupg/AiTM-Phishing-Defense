"""
Unit & API tests for Module 4 User-Training Lessons and Interactive Quiz.
Covers:
- All 9 required cybersecurity awareness lessons & structured content
- Minimum 10 quiz questions (12 total: 8 reused from Module 3 + 4 extended)
- 4 options per question, 1 correct answer
- Immediate per-question feedback and explanation
- Final score, percentage, and pass/fail result calculation
"""

import sys
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from module4_soc_dashboard.backend.app import create_app
from module4_soc_dashboard.backend.integration_service import ModuleIntegrationService


@pytest.fixture()
def client():
    service = ModuleIntegrationService(force_fallback=True)
    return TestClient(create_app(integration_service=service))


def test_training_lessons_cover_all_nine_topics(client):
    res = client.get("/api/m4/training/lessons")
    assert res.status_code == 200
    data = res.json()
    assert data["total_lessons"] == 9
    lessons = data["lessons"]
    assert len(lessons) == 9

    for lesson in lessons:
        assert lesson["title"]
        assert lesson["simple_explanation"]
        assert lesson["practical_example"]
        assert len(lesson["warning_signs"]) >= 2
        assert len(lesson["prevention_techniques"]) >= 2


def test_quiz_has_at_least_ten_questions_with_four_options(client):
    res = client.get("/api/m4/training/quiz")
    assert res.status_code == 200
    data = res.json()
    questions = data["questions"]
    assert len(questions) >= 10
    assert data["total_questions"] == len(questions)

    for q in questions:
        assert "question_id" in q
        assert "question" in q
        assert len(q["options"]) == 4
        # Ensure answer key is never leaked to frontend payload
        assert "correct_index" not in q


def test_immediate_question_feedback(client):
    # Q-01 correct_index is 1 (from module3_hardening.training_quiz)
    ok_res = client.post("/api/m4/training/quiz/check", json={"question_id": "Q-01", "selected_index": 1})
    assert ok_res.status_code == 200
    assert ok_res.json()["is_correct"] is True
    assert ok_res.json()["explanation"]

    bad_res = client.post("/api/m4/training/quiz/check", json={"question_id": "Q-01", "selected_index": 0})
    assert bad_res.status_code == 200
    assert bad_res.json()["is_correct"] is False
    assert bad_res.json()["correct_index"] == 1

    unknown = client.post("/api/m4/training/quiz/check", json={"question_id": "Q-999", "selected_index": 0})
    assert unknown.status_code == 404


def test_quiz_scoring_pass_and_fail(client):
    perfect_answers = {
        "Q-01": 1,
        "Q-02": 1,
        "Q-03": 1,
        "Q-04": 2,
        "Q-05": 1,
        "Q-06": 1,
        "Q-07": 1,
        "Q-08": 1,
        "Q-09": 1,
        "Q-10": 2,
        "Q-11": 1,
        "Q-12": 1,
    }
    pass_res = client.post("/api/m4/training/quiz/submit", json={"answers": perfect_answers})
    assert pass_res.status_code == 200
    pass_data = pass_res.json()
    assert pass_data["total_questions"] == 12
    assert pass_data["correct_answers"] == 12
    assert pass_data["score_percentage"] == 100.0
    assert pass_data["passed"] is True

    zero_res = client.post("/api/m4/training/quiz/submit", json={"answers": {"Q-01": 0}})
    assert zero_res.status_code == 200
    zero_data = zero_res.json()
    assert zero_data["correct_answers"] == 0
    assert zero_data["score_percentage"] == 0.0
    assert zero_data["passed"] is False
