"""
V4 — tests for the public gallery (opt-in scan publish).

Covers the pure helpers that shape what gets written to public_scans:
  - _gallery_group: fine-grained check category -> one of 5 buckets
  - _grade_from_score: pass-ratio grade cutoffs (A/B/C/D/F)
  - _compute_category_summary: grouping + per-bucket grade math

Also smoke-tests db.* gallery helpers in the "DB not configured" mode —
they must fail closed (return empty/False/None) instead of raising, so
local dev and test environments without Supabase creds don't blow up.

Run with:
    cd security-scanner
    python -m pytest tests/test_public_gallery.py -v
"""
import pytest

import db
from api import (
    _gallery_group,
    _grade_from_score,
    _compute_category_summary,
    _GALLERY_CATEGORY_MAP,
    _GALLERY_PUBLISH_LIMIT_24H,
)


# ----------------------------------------------------------------------
# _gallery_group — fine-grained category projection
# ----------------------------------------------------------------------

def test_gallery_group_maps_known_buckets_verbatim():
    assert _gallery_group("SEO") == "SEO"
    assert _gallery_group("Performance") == "Performance"
    assert _gallery_group("GDPR") == "GDPR"
    assert _gallery_group("Accessibility") == "Accessibility"


def test_gallery_group_security_is_default_bucket():
    # Every check category not in the map must fall into "Security" —
    # this is the safe default so brand-new check modules don't silently
    # disappear from the gallery detail page.
    for cat in (
        "SSL/TLS",
        "Security Headers",
        "Cookie Security",
        "DNS Security",
        "Ports",
        "API Security",
        "XSS",
        "SQL Injection",
        "CSRF",
        "Headers",
        "",
        "completely-unknown-future-category",
    ):
        assert _gallery_group(cat) == "Security", cat


def test_gallery_group_handles_none_like_input():
    # Defensive: category="" is how the publish endpoint passes missing
    # categories; must not raise.
    assert _gallery_group("") == "Security"


def test_gallery_category_map_only_maps_non_security_buckets():
    # Security is intentionally NOT in the map — it's the fallback.
    assert "Security" not in _GALLERY_CATEGORY_MAP


# ----------------------------------------------------------------------
# _grade_from_score — pass-ratio thresholds
# ----------------------------------------------------------------------

@pytest.mark.parametrize(
    "score,expected",
    [
        (100, "A"),
        (95, "A"),
        (90, "A"),
        (89, "B"),
        (80, "B"),
        (79, "C"),
        (70, "C"),
        (69, "D"),
        (60, "D"),
        (59, "F"),
        (0, "F"),
    ],
)
def test_grade_from_score_thresholds(score, expected):
    assert _grade_from_score(score) == expected


# ----------------------------------------------------------------------
# _compute_category_summary — grouping + per-bucket math
# ----------------------------------------------------------------------

def _r(category: str, passed: bool = True) -> dict:
    return {"category": category, "passed": passed, "severity": "INFO"}


def test_category_summary_empty_input_returns_empty_dict():
    assert _compute_category_summary([]) == {}


def test_category_summary_omits_empty_buckets():
    # Only SEO has tests — the other four buckets must not appear at all.
    out = _compute_category_summary([_r("SEO", True), _r("SEO", False)])
    assert set(out.keys()) == {"SEO"}
    assert out["SEO"]["total"] == 2
    assert out["SEO"]["passed"] == 1
    assert out["SEO"]["score"] == 50
    assert out["SEO"]["grade"] == "F"


def test_category_summary_groups_security_catchall():
    # Three distinct fine-grained categories, all should collapse into Security.
    results = [
        _r("SSL/TLS", True),
        _r("Security Headers", True),
        _r("DNS Security", False),
    ]
    out = _compute_category_summary(results)
    assert set(out.keys()) == {"Security"}
    assert out["Security"]["total"] == 3
    assert out["Security"]["passed"] == 2
    # 2/3 = 67% rounded → 67 → D
    assert out["Security"]["score"] == 67
    assert out["Security"]["grade"] == "D"


def test_category_summary_all_five_buckets_present_when_populated():
    results = [
        _r("Headers", True),        # Security
        _r("SEO", True),
        _r("Performance", False),
        _r("GDPR", True),
        _r("Accessibility", False),
    ]
    out = _compute_category_summary(results)
    assert set(out.keys()) == {
        "Security", "SEO", "Performance", "GDPR", "Accessibility"
    }
    for bucket in out.values():
        assert bucket["total"] == 1


def test_category_summary_perfect_pass_gives_a():
    results = [_r("SEO", True) for _ in range(10)]
    out = _compute_category_summary(results)
    assert out["SEO"]["score"] == 100
    assert out["SEO"]["grade"] == "A"


def test_category_summary_all_fail_gives_f():
    results = [_r("Performance", False) for _ in range(4)]
    out = _compute_category_summary(results)
    assert out["Performance"]["score"] == 0
    assert out["Performance"]["grade"] == "F"


def test_category_summary_missing_category_falls_to_security():
    # A result dict with no "category" key must still land somewhere —
    # in the "Security" bucket, since that's the safe default.
    out = _compute_category_summary([{"passed": True, "severity": "INFO"}])
    assert "Security" in out
    assert out["Security"]["total"] == 1


def test_category_summary_passed_missing_treated_as_fail():
    # Some checks emit results without "passed" (regression risk). Treat
    # as failed so the user isn't shown a falsely inflated grade.
    out = _compute_category_summary([{"category": "SEO"}])
    assert out["SEO"]["passed"] == 0
    assert out["SEO"]["score"] == 0
    assert out["SEO"]["grade"] == "F"


# ----------------------------------------------------------------------
# PUBLIC_SORT_MODES — the tuple the endpoint validates against
# ----------------------------------------------------------------------

def test_public_sort_modes_is_exact_set():
    assert set(db.PUBLIC_SORT_MODES) == {
        "newest", "top_score", "top_paranoid", "top_strict"
    }


def test_gallery_publish_limit_is_sane():
    # Not zero (would lock users out), not huge (would defeat rate limit).
    assert 1 <= _GALLERY_PUBLISH_LIMIT_24H <= 100


# ----------------------------------------------------------------------
# db.* gallery helpers — must fail-closed when Supabase is not configured
#
# In dev / CI we don't want importing db + calling these helpers to raise.
# They should all return the equivalent of "nothing here" so the API layer
# can surface a sane 404/409 instead of a 500.
# ----------------------------------------------------------------------

def _force_db_unconfigured(monkeypatch):
    monkeypatch.setattr(db, "is_configured", lambda: False)


def test_publish_scan_returns_false_when_db_not_configured(monkeypatch):
    _force_db_unconfigured(monkeypatch)
    ok = db.publish_scan(
        scan_id="x",
        url="https://example.com",
        domain="example.com",
        score=90,
        grade="A",
        strictness="standard",
        total_checks=1,
        failed_checks=0,
        counts={"critical": 0, "high": 0, "medium": 0, "low": 0},
        categories={},
        publisher_ip="1.2.3.4",
    )
    assert ok is False


def test_withdraw_scan_returns_false_when_db_not_configured(monkeypatch):
    _force_db_unconfigured(monkeypatch)
    assert db.withdraw_scan("x", client_ip="1.2.3.4") is False


def test_list_public_scans_returns_empty_when_db_not_configured(monkeypatch):
    _force_db_unconfigured(monkeypatch)
    assert db.list_public_scans() == []


def test_get_public_scan_returns_none_when_db_not_configured(monkeypatch):
    _force_db_unconfigured(monkeypatch)
    assert db.get_public_scan("x") is None


def test_count_recent_publishes_returns_zero_when_db_not_configured(monkeypatch):
    _force_db_unconfigured(monkeypatch)
    assert db.count_recent_publishes_by_ip("1.2.3.4") == 0


def test_owner_check_returns_none_when_db_not_configured(monkeypatch):
    _force_db_unconfigured(monkeypatch)
    assert db.get_public_scan_for_owner_check("x") is None


# ----------------------------------------------------------------------
# list_public_scans — input validation layer (still runs when DB is off,
# because the clamping happens before the DB call)
# ----------------------------------------------------------------------

def test_list_public_scans_invalid_sort_falls_back_to_newest(monkeypatch):
    # We don't hit the real DB; we just assert that bad input doesn't crash
    # and that the unconfigured branch still returns an empty list cleanly.
    _force_db_unconfigured(monkeypatch)
    assert db.list_public_scans(sort_by="definitely-not-a-mode") == []


@pytest.mark.parametrize("bad_limit", [0, -5, None])
def test_list_public_scans_accepts_edge_limits(monkeypatch, bad_limit):
    _force_db_unconfigured(monkeypatch)
    # Must not raise — internal clamp handles bad limit values.
    assert db.list_public_scans(limit=bad_limit) == []
