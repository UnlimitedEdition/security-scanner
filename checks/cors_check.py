"""
CORS (Cross-Origin Resource Sharing) Security Check
Checks for overly permissive CORS configuration.
"""
import requests
from typing import List, Dict, Any

TIMEOUT = 8


def run(base_url: str, response_headers: dict, session: requests.Session) -> List[Dict[str, Any]]:
    results = []
    lower_headers = {k.lower(): v for k, v in response_headers.items()}

    # Check CORS on main page first
    acao = lower_headers.get("access-control-allow-origin", "")
    acac = lower_headers.get("access-control-allow-credentials", "").lower()

    # Also check API endpoints which often have CORS
    api_endpoints = ["/api/", "/api/v1/", "/api/v2/", "/graphql", "/wp-json/"]
    api_cors = None
    for ep in api_endpoints:
        try:
            test_url = base_url.rstrip("/") + ep
            # Send a cross-origin preflight simulation
            resp = session.get(
                test_url,
                timeout=TIMEOUT,
                headers={"Origin": "https://evil-attacker.com"}
            )
            api_acao = resp.headers.get("Access-Control-Allow-Origin", "")
            if api_acao:
                api_cors = (ep, api_acao, resp.headers.get("Access-Control-Allow-Credentials", ""))
                break
        except Exception:
            pass

    # Evaluate main page CORS
    cors_to_check = [(acao, acac, "główna stranica")]
    if api_cors:
        cors_to_check.append((api_cors[1], api_cors[2].lower(), f"API endpoint {api_cors[0]}"))

    found_issue = False
    for origin_val, creds_val, location in cors_to_check:
        if not origin_val:
            continue

        if origin_val == "*":
            if creds_val == "true":
                # This is the most dangerous combination
                results.append({
                    "id": "cors_wildcard_with_credentials",
                    "category": "CORS Policy",
                    "severity": "CRITICAL",
                    "passed": False,
                    "title": f"CORS: Wildcard (*) + credentials=true — kritična ranjivost! ({location})",
                    "title_en": f"CORS: Wildcard (*) + credentials=true — critical vulnerability! ({location})",
                    "description": "CORS wildcard sa credentials=true dozvoljava BILO kojoj veb stranici da šalje autentifikovane zahteve u ime korisnika. Ovo je kritična sigurnosna ranjivost.",
                    "description_en": "CORS wildcard with credentials=true allows ANY website to send authenticated requests on behalf of users. This is a critical security vulnerability.",
                    "recommendation": "Nikada ne kombinujte Access-Control-Allow-Origin: * sa Access-Control-Allow-Credentials: true. Koristite specifičan origin umesto wildcard-a.",
                    "recommendation_en": "Never combine Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true. Use a specific origin instead of a wildcard.",
                })
                found_issue = True
            else:
                results.append({
                    "id": "cors_wildcard",
                    "category": "CORS Policy",
                    "severity": "MEDIUM",
                    "passed": False,
                    "title": f"CORS: Wildcard (*) dozvoljava pristup sa svih domena ({location})",
                    "title_en": f"CORS: Wildcard (*) allows access from all domains ({location})",
                    "description": "Access-Control-Allow-Origin: * znači da svaka veb stranica može čitati odgovore vašeg API-ja. Za javne API-je ovo može biti OK, ali za stranice sa podacima korisnika — nije.",
                    "description_en": "Access-Control-Allow-Origin: * means any website can read your API responses. For public APIs this may be OK, but for pages with user data — it is not.",
                    "recommendation": "Ograničite CORS na specifične domene: Access-Control-Allow-Origin: https://vasajt.com",
                    "recommendation_en": "Restrict CORS to specific domains: Access-Control-Allow-Origin: https://yourdomain.com",
                })
                found_issue = True

        elif origin_val and origin_val != "*":
            # Reflected origin — dynamic CORS without whitelist check
            if "evil-attacker.com" in origin_val:
                results.append({
                    "id": "cors_reflected_origin",
                    "category": "CORS Policy",
                    "severity": "HIGH",
                    "passed": False,
                    "title": f"CORS: Server reflektuje Origin bez provere ({location})",
                    "title_en": f"CORS: Server reflects Origin without validation ({location})",
                    "description": "Server kopira Origin header iz zahteva direktno u Access-Control-Allow-Origin response. Ovo je ekvivalentno wildcard CORS-u i dozvoljava cross-origin napade.",
                    "description_en": "Server copies the Origin header from the request directly into the Access-Control-Allow-Origin response. This is equivalent to wildcard CORS and allows cross-origin attacks.",
                    "recommendation": "Implementirajte whitelist proverom: dozvolite samo specifične, hardcoded domene.",
                    "recommendation_en": "Implement whitelist checking: allow only specific, hardcoded domains.",
                })
                found_issue = True

    if not found_issue:
        results.append({
            "id": "cors_ok",
            "category": "CORS Policy",
            "severity": "INFO",
            "passed": True,
            "title": "CORS politika izgleda bezbedno ✓",
            "title_en": "CORS policy looks safe ✓",
            "description": "Nije detektovana preširoka CORS konfiguracija.",
            "description_en": "No overly permissive CORS configuration detected.",
            "recommendation": "",
            "recommendation_en": "",
        })

    return results
