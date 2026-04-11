# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Toske-Programer (Web Security Scanner contributors)
"""
Mozilla Observatory Integration
Queries Mozilla HTTP Observatory API for an independent security grade.
API docs: https://http-observatory.security.mozilla.org/api/v1/
No API key required.
"""
import requests
from typing import List, Dict, Any

API_BASE = "https://http-observatory.security.mozilla.org/api/v1"
TIMEOUT = 15


def run(domain: str) -> List[Dict[str, Any]]:
    results = []

    try:
        # Start a scan (or get cached results)
        resp = requests.post(
            f"{API_BASE}/analyze",
            data={"host": domain, "hidden": "true"},
            timeout=TIMEOUT,
        )

        if resp.status_code != 200:
            return results

        data = resp.json()
        state = data.get("state", "")

        # If scan is running, wait and retry once
        if state in ("PENDING", "RUNNING", "STARTING"):
            import time
            time.sleep(5)
            resp = requests.get(
                f"{API_BASE}/analyze?host={domain}",
                timeout=TIMEOUT,
            )
            if resp.status_code == 200:
                data = resp.json()
                state = data.get("state", "")

        if state != "FINISHED":
            return results

        grade = data.get("grade", "")
        score = data.get("score", 0)
        tests_passed = data.get("tests_passed", 0)
        tests_failed = data.get("tests_failed", 0)
        tests_total = tests_passed + tests_failed

        # Map Mozilla grade to our severity
        if grade in ("A+", "A"):
            severity = "INFO"
            passed = True
            title_sr = f"Mozilla Observatory: {grade} ({score}/100)"
            title_en = f"Mozilla Observatory: {grade} ({score}/100)"
            desc_sr = f"Mozilla ocenjuje vas sajt sa {grade} ({score}/100). {tests_passed}/{tests_total} testova proslo. Odlicna bezbednost."
            desc_en = f"Mozilla rates your site {grade} ({score}/100). {tests_passed}/{tests_total} tests passed. Excellent security."
        elif grade in ("B+", "B"):
            severity = "LOW"
            passed = False
            title_sr = f"Mozilla Observatory: {grade} ({score}/100) — dobro ali moze bolje"
            title_en = f"Mozilla Observatory: {grade} ({score}/100) — good but can improve"
            desc_sr = f"Mozilla ocenjuje sajt sa {grade}. {tests_failed} testova nije proslo. Pogledajte detalje na observatory.mozilla.org."
            desc_en = f"Mozilla rates your site {grade}. {tests_failed} tests failed. See details at observatory.mozilla.org."
        elif grade in ("C+", "C"):
            severity = "MEDIUM"
            passed = False
            title_sr = f"Mozilla Observatory: {grade} ({score}/100) — osrednje"
            title_en = f"Mozilla Observatory: {grade} ({score}/100) — fair"
            desc_sr = f"Sajt ima {grade} ocenu. {tests_failed} bezbednosnih testova nije proslo."
            desc_en = f"Site has {grade} grade. {tests_failed} security tests failed."
        else:
            severity = "HIGH"
            passed = False
            title_sr = f"Mozilla Observatory: {grade} ({score}/100) — lose"
            title_en = f"Mozilla Observatory: {grade} ({score}/100) — poor"
            desc_sr = f"Mozilla ocenjuje sajt sa {grade}. Ozbiljni bezbednosni propusti detektovani. {tests_failed} testova palo."
            desc_en = f"Mozilla rates your site {grade}. Serious security issues detected. {tests_failed} tests failed."

        results.append({
            "id": "observatory_grade",
            "category": "Mozilla Observatory",
            "severity": severity,
            "passed": passed,
            "title": title_sr,
            "title_en": title_en,
            "description": desc_sr,
            "description_en": desc_en,
            "recommendation": "Pogledajte kompletan izvestaj: https://observatory.mozilla.org/analyze/" + domain,
            "recommendation_en": "View full report: https://observatory.mozilla.org/analyze/" + domain,
        })

        # Get detailed test results
        try:
            tests_resp = requests.get(
                f"{API_BASE}/getScanResults?scan={data.get('scan_id', '')}",
                timeout=TIMEOUT,
            )
            if tests_resp.status_code == 200:
                tests = tests_resp.json()
                failed_tests = []
                for test_name, test_data in tests.items():
                    if not test_data.get("pass", True):
                        failed_tests.append({
                            "name": test_data.get("name", test_name),
                            "result": test_data.get("result", ""),
                            "score": test_data.get("score_modifier", 0),
                        })

                if failed_tests:
                    # Sort by impact (most negative score first)
                    failed_tests.sort(key=lambda x: x["score"])
                    details = []
                    for ft in failed_tests[:8]:
                        details.append(f"{ft['name']}: {ft['result']} ({ft['score']} pts)")

                    results.append({
                        "id": "observatory_details",
                        "category": "Mozilla Observatory",
                        "severity": "INFO",
                        "passed": True,
                        "title": f"Observatory detalji: {len(failed_tests)} neuspelih testova",
                        "title_en": f"Observatory details: {len(failed_tests)} failed tests",
                        "description": " | ".join(details),
                        "description_en": " | ".join(details),
                        "recommendation": "",
                        "recommendation_en": "",
                    })
        except Exception:
            pass

    except requests.exceptions.Timeout:
        pass
    except Exception:
        pass

    return results
