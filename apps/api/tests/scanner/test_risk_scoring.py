"""Transparent risk scoring and stable severity tests."""

from sentinel_api.scanner.analysis.models import RiskScoreComponent
from sentinel_api.scanner.analysis.risk_scoring import RiskScorer, severity_for_score


def test_bola_score_is_stable_and_components_sum() -> None:
    score = RiskScorer().bola("read_one")

    assert score.score == 82
    assert score.severity == "high"
    assert sum(component.points for component in score.components) == score.score
    assert RiskScorer().bola("read_one") == score


def test_update_and_delete_score_above_read() -> None:
    scorer = RiskScorer()

    assert scorer.bola("read_one").score < scorer.bola("update").score
    assert scorer.bola("read_one").score < scorer.bola("delete").score


def test_severity_boundaries() -> None:
    assert severity_for_score(24) == "informational"
    assert severity_for_score(25) == "low"
    assert severity_for_score(44) == "low"
    assert severity_for_score(45) == "medium"
    assert severity_for_score(64) == "medium"
    assert severity_for_score(65) == "high"
    assert severity_for_score(84) == "high"
    assert severity_for_score(85) == "critical"


def test_score_caps_at_one_hundred() -> None:
    score = RiskScorer.from_components(
        [RiskScoreComponent(name="large", points=120)]
    )

    assert score.score == 100
    assert score.severity == "critical"
