# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Toske-Programer (Web Security Scanner contributors)
"""
Risk Engine
Analyzes scan results and produces prioritized recommendations.
Calculates risk score per finding and generates "Top 5 priorities".
"""
from typing import List, Dict, Any

SEVERITY_WEIGHT = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 1,
    "INFO": 0,
}

# Difficulty to fix (estimated)
FIX_DIFFICULTY = {
    # Headers - easy
    "hdr_hsts": "easy", "hdr_csp": "medium", "hdr_xfo": "easy",
    "hdr_xcto": "easy", "hdr_rp": "easy", "hdr_pp": "easy", "hdr_coop": "easy",
    # SSL - medium
    "ssl_cert_expired": "easy", "ssl_cert_expiring_soon": "easy",
    "ssl_weak_tls": "medium", "ssl_weak_cipher": "medium",
    "ssl_no_https": "medium", "ssl_cert_invalid": "medium",
    # DNS - medium
    "dns_spf_missing": "medium", "dns_dmarc_missing": "medium",
    "dns_dnssec_missing": "hard",
    # Files - easy
    "file_env": "easy", "file_git_config": "easy",
    # Cookies
    "cookies_no_httponly": "easy", "cookies_no_secure": "easy",
    # CORS
    "cors_wildcard_with_credentials": "easy", "cors_wildcard": "easy",
    # Redirects
    "redirect_no_https": "medium",
    # SEO
    "seo_title_missing": "easy", "seo_desc_missing": "easy",
    "seo_h1_missing": "easy", "seo_og_missing": "easy",
    "seo_sitemap_missing": "medium", "seo_canonical_missing": "easy",
    # Vuln
    "vuln_sql_leak": "hard", "vuln_error_leak": "medium",
    "vuln_dir_listing": "easy", "vuln_csrf": "medium",
    # JS
    "js_api_keys": "easy", "js_vuln_libs": "medium",
    # API
    "api_graphql_introspection": "easy", "api_swagger_exposed": "easy",
    # GDPR
    "gdpr_privacy_policy": "medium", "gdpr_cookie_consent": "medium",
    "gdpr_trackers_no_consent": "medium",
    # Performance
    "perf_compression": "easy", "perf_cache": "easy",
}


def calculate_risk_score(item):
    """Calculate risk score for a single finding."""
    if item.get("passed", True):
        return 0

    severity = item.get("severity", "LOW")
    weight = SEVERITY_WEIGHT.get(severity, 1)

    # Confidence based on check type
    confidence = 1.0
    check_id = item.get("id", "")
    if "potential" in check_id or "possible" in check_id:
        confidence = 0.6

    # Exposure: how publicly visible is this issue
    exposure = 0.8
    category = item.get("category", "")
    if category in ("SSL/TLS", "Security Headers", "Redirects"):
        exposure = 1.0  # Visible to everyone
    elif category in ("Admin Exposure", "Sensitive Files"):
        exposure = 0.9
    elif category in ("DNS Security",):
        exposure = 0.7

    return round(weight * confidence * exposure, 1)


# Fallback difficulty by check-ID prefix, used when a specific check_id is
# not listed in FIX_DIFFICULTY above. Explicit and ordered — no more relying
# on dict iteration order or fuzzy rsplit matches.
CATEGORY_DEFAULT_DIFFICULTY = {
    "hdr_":       "easy",
    "cookies_":   "easy",
    "cors_":      "easy",
    "seo_":       "easy",
    "file_":      "easy",
    "admin_":     "easy",
    "api_":       "easy",
    "extras_":    "easy",
    "perf_":      "easy",
    "ssl_":       "medium",
    "dns_":       "medium",
    "redirect_":  "medium",
    "vuln_":      "medium",
    "gdpr_":      "medium",
    "js_":        "medium",
    "cms_":       "medium",
    "ports_":     "medium",
    "dep_":       "medium",
    "dependency_": "medium",
    "whois_":     "hard",
    "subdomain_": "hard",
    "ct_":        "hard",
}


def get_fix_difficulty(check_id):
    """Get estimated difficulty to fix this issue."""
    # Exact match always wins — FIX_DIFFICULTY is the source of truth
    if check_id in FIX_DIFFICULTY:
        return FIX_DIFFICULTY[check_id]
    # Explicit prefix fallback — deterministic and easy to audit
    for prefix, diff in CATEGORY_DEFAULT_DIFFICULTY.items():
        if check_id.startswith(prefix):
            return diff
    return "medium"


def prioritize(results):
    """
    Take scan results, return top priorities with risk scores.
    Returns list of dicts with: item, risk_score, fix_difficulty, priority_rank
    """
    scored = []
    for item in results:
        if item.get("passed", True):
            continue
        score = calculate_risk_score(item)
        if score <= 0:
            continue
        difficulty = get_fix_difficulty(item.get("id", ""))
        # Boost easy fixes (better ROI)
        roi_boost = {"easy": 1.3, "medium": 1.0, "hard": 0.7}.get(difficulty, 1.0)
        final_score = round(score * roi_boost, 1)

        scored.append({
            "item": item,
            "risk_score": score,
            "final_score": final_score,
            "fix_difficulty": difficulty,
        })

    # Sort by final_score descending
    scored.sort(key=lambda x: x["final_score"], reverse=True)

    # Add priority rank
    for i, entry in enumerate(scored):
        entry["priority_rank"] = i + 1

    return scored


def get_top_priorities(results, count=5):
    """Get top N priorities with explanations."""
    all_priorities = prioritize(results)
    top = all_priorities[:count]

    priorities = []
    for entry in top:
        item = entry["item"]
        diff_labels = {
            "easy": {"sr": "Lako", "en": "Easy"},
            "medium": {"sr": "Srednje", "en": "Medium"},
            "hard": {"sr": "Tesko", "en": "Hard"},
        }
        diff = diff_labels.get(entry["fix_difficulty"], diff_labels["medium"])

        priorities.append({
            "rank": entry["priority_rank"],
            "title": item.get("title", ""),
            "title_en": item.get("title_en", ""),
            "category": item.get("category", ""),
            "severity": item.get("severity", ""),
            "risk_score": entry["risk_score"],
            "fix_difficulty": entry["fix_difficulty"],
            "fix_difficulty_sr": diff["sr"],
            "fix_difficulty_en": diff["en"],
            "recommendation": item.get("recommendation", ""),
            "recommendation_en": item.get("recommendation_en", ""),
        })

    return priorities


