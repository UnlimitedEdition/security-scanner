"""
V4 — tests for scanner.compute_score() strictness profiles.

The "standard" profile MUST reproduce V3 scoring exactly. That is the
regression gate: any change to scoring must keep standard-mode numbers
identical, or every historical scan suddenly changes meaning.

Run with:
    cd security-scanner
    python -m pytest tests/test_strictness.py -v

No network, no fixtures on disk — everything is synthetic input dicts
shaped exactly like scanner.py check outputs.
"""
import pytest

from scanner import (
    compute_score,
    STRICTNESS_PROFILES,
    DEFAULT_STRICTNESS,
)


def _fail(category: str, severity: str) -> dict:
    return {"category": category, "severity": severity, "passed": False}


def _info_pass(category: str = "Headers") -> dict:
    return {"category": category, "severity": "INFO", "passed": True}


# ----------------------------------------------------------------------
# Basic invariants
# ----------------------------------------------------------------------

def test_default_is_standard():
    assert DEFAULT_STRICTNESS == "standard"


def test_all_four_profiles_registered():
    assert set(STRICTNESS_PROFILES.keys()) == {"basic", "standard", "strict", "paranoid"}


def test_empty_results_perfect_score_every_profile():
    for name in STRICTNESS_PROFILES:
        out = compute_score([], strictness=name)
        assert out["score"] == 100, f"{name}: expected 100, got {out['score']}"
        assert out["grade"] == "A", f"{name}: expected A, got {out['grade']}"


def test_unknown_strictness_falls_back_to_standard():
    out_bad = compute_score([], strictness="nonsense")
    out_std = compute_score([], strictness="standard")
    assert out_bad["strictness"] == "standard"
    assert out_bad["score"] == out_std["score"]


def test_none_strictness_falls_back_to_default():
    # type: ignore[arg-type] — explicitly testing None/fallback behavior
    out = compute_score([], strictness=None)  # type: ignore
    assert out["strictness"] == DEFAULT_STRICTNESS


# ----------------------------------------------------------------------
# V3 regression gate — "standard" must match pre-V4 scoring byte-for-byte
# ----------------------------------------------------------------------

def test_standard_regression_v3_single_critical():
    # V3: 1 CRITICAL → -20, no bonus → 80
    out = compute_score([_fail("Headers", "CRITICAL")], strictness="standard")
    assert out["score"] == 80
    assert out["grade"] == "B"
    assert out["counts"]["critical"] == 1


def test_standard_regression_v3_diminishing_cap_critical():
    # V3: CRITICAL cap at 3 → 5 fails still count as 3 × 20 = -60 → 40
    fails = [_fail("Headers", "CRITICAL") for _ in range(5)]
    out = compute_score(fails, strictness="standard")
    assert out["score"] == 40
    assert out["counts"]["critical"] == 5  # raw count preserved even though cap applies to penalty


def test_standard_regression_v3_bonus_per_info():
    # V3: 5 INFO passes × 2 = +10 bonus, no fails → min(100, 100+10) = 100
    passes = [_info_pass() for _ in range(5)]
    out = compute_score(passes, strictness="standard")
    assert out["score"] == 100


def test_standard_regression_v3_bonus_cap():
    # V3: bonus capped at 20 → 50 INFO passes still = +20, score stays 100
    passes = [_info_pass() for _ in range(50)]
    out = compute_score(passes, strictness="standard")
    assert out["score"] == 100


def test_standard_regression_v3_mixed_fixture():
    # Fixed mixed input = exact legacy expected score.
    # 1 CRITICAL (-20) + 2 HIGH (-20) + 1 MEDIUM (-5) + 1 LOW (-2) = -47
    # SEO failure EXCLUDED from standard.
    # 2 INFO passes × 2 = +4 bonus.
    # Score = 100 - 47 + 4 = 57 → grade D (thresholds A=90,B=75,C=60,D=40).
    fixture = [
        _fail("Headers", "CRITICAL"),
        _fail("Headers", "HIGH"),
        _fail("Headers", "HIGH"),
        _fail("Headers", "MEDIUM"),
        _fail("Headers", "LOW"),
        _fail("SEO", "HIGH"),
        _info_pass(),
        _info_pass(),
    ]
    out = compute_score(fixture, strictness="standard")
    assert out["score"] == 57
    assert out["grade"] == "D"
    assert out["counts"]["high"] == 2  # SEO HIGH was excluded before counting


# ----------------------------------------------------------------------
# Escalation — same input, score must decrease (or equal) as strictness rises
# ----------------------------------------------------------------------

def test_strictness_escalation_monotonic():
    fixture = [
        _fail("Headers", "CRITICAL"),
        _fail("Headers", "HIGH"),
        _fail("Headers", "HIGH"),
        _fail("Headers", "MEDIUM"),
        _fail("Headers", "LOW"),
        _fail("SEO", "HIGH"),
        _info_pass(),
        _info_pass(),
    ]
    scores = {
        name: compute_score(fixture, strictness=name)["score"]
        for name in ("basic", "standard", "strict", "paranoid")
    }
    # strictly decreasing for this fixture (not a profile invariant in general,
    # but holds for any fixture with ≥1 non-excluded failure)
    assert scores["basic"] >= scores["standard"] >= scores["strict"] >= scores["paranoid"]
    assert scores["basic"] > scores["paranoid"], (
        f"basic ({scores['basic']}) must be > paranoid ({scores['paranoid']}) on mixed fixture"
    )


# ----------------------------------------------------------------------
# Excluded categories per profile
# ----------------------------------------------------------------------

def test_basic_excludes_seo_gdpr_accessibility_performance():
    # A HIGH in each excluded category must not dent the basic score.
    fixture = [
        _fail("SEO", "HIGH"),
        _fail("GDPR", "HIGH"),
        _fail("Accessibility", "HIGH"),
        _fail("Performance", "HIGH"),
    ]
    out = compute_score(fixture, strictness="basic")
    assert out["score"] == 100


def test_standard_excludes_same_four_as_basic():
    fixture = [
        _fail("SEO", "CRITICAL"),
        _fail("GDPR", "CRITICAL"),
        _fail("Accessibility", "CRITICAL"),
        _fail("Performance", "CRITICAL"),
    ]
    out = compute_score(fixture, strictness="standard")
    assert out["score"] == 100  # none of these are security categories in V3


def test_strict_counts_seo_and_gdpr():
    # strict excludes only Accessibility + Performance → SEO/GDPR count
    fixture = [_fail("SEO", "HIGH")]
    out = compute_score(fixture, strictness="strict")
    # No diminishing → 1 HIGH × 15 = -15 → 85, plus bonus 0 → 85
    assert out["score"] == 85


def test_paranoid_counts_every_category():
    fixture = [_fail("Accessibility", "HIGH")]
    out = compute_score(fixture, strictness="paranoid")
    # Paranoid: HIGH = 20, no diminishing → 100 - 20 = 80
    assert out["score"] == 80


# ----------------------------------------------------------------------
# Diminishing vs flat penalties
# ----------------------------------------------------------------------

def test_basic_and_standard_apply_diminishing_caps():
    # 10 HIGH failures in a security category. Basic+standard cap HIGH at 4.
    fails = [_fail("Headers", "HIGH") for _ in range(10)]
    basic = compute_score(fails, strictness="basic")
    standard = compute_score(fails, strictness="standard")
    # basic HIGH weight 6, cap 4 → -24 → 76
    assert basic["score"] == 76
    # standard HIGH weight 10, cap 4 → -40 → 60
    assert standard["score"] == 60


def test_strict_and_paranoid_have_no_cap():
    fails = [_fail("Headers", "HIGH") for _ in range(10)]
    strict = compute_score(fails, strictness="strict")
    paranoid = compute_score(fails, strictness="paranoid")
    # strict: HIGH=15 × 10 = -150 → clamped to score floor 5
    assert strict["score"] == 5
    # paranoid: HIGH=20 × 10 = -200 → floor 5
    assert paranoid["score"] == 5


def test_score_floor_is_five():
    fails = [_fail("Headers", "CRITICAL") for _ in range(100)]
    for name in STRICTNESS_PROFILES:
        out = compute_score(fails, strictness=name)
        assert out["score"] >= 5, f"{name} went below floor"


# ----------------------------------------------------------------------
# Grade thresholds
# ----------------------------------------------------------------------

def test_paranoid_a_requires_exactly_100():
    # One LOW failure (LOW weight 7, no diminishing) → 93 → A threshold=100 fails → B
    out = compute_score([_fail("Headers", "LOW")], strictness="paranoid")
    assert out["score"] == 93
    assert out["grade"] == "B"


def test_standard_a_at_90():
    # 1 HIGH (-10) + 5 INFO passes (+10) = 100
    fixture = [_fail("Headers", "HIGH")] + [_info_pass() for _ in range(5)]
    out = compute_score(fixture, strictness="standard")
    assert out["score"] == 100
    assert out["grade"] == "A"


def test_basic_a_at_85():
    # 1 CRITICAL (basic weight 15) → 85 exactly → A
    out = compute_score([_fail("Headers", "CRITICAL")], strictness="basic")
    assert out["score"] == 85
    assert out["grade"] == "A"


# ----------------------------------------------------------------------
# Profile payload shape
# ----------------------------------------------------------------------

def test_result_includes_strictness_field():
    out = compute_score([], strictness="strict")
    assert out["strictness"] == "strict"


def test_result_has_all_required_keys():
    out = compute_score([], strictness="standard")
    for key in ("score", "grade", "grade_color", "grade_label", "counts", "strictness"):
        assert key in out
    for sev in ("critical", "high", "medium", "low"):
        assert sev in out["counts"]
