"""
API Security Check
Checks: GraphQL introspection, API endpoint discovery, Swagger/OpenAPI exposure,
unauthenticated API access, CORS on API endpoints.
"""
import sys
import os
import requests
from typing import List, Dict, Any

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from security_utils import safe_get, safe_head, safe_post, UnsafeTargetError

TIMEOUT = 7


def _pass(check_id, title_sr, title_en, desc_sr, desc_en):
    return {
        "id": check_id, "category": "API Security", "severity": "INFO", "passed": True,
        "title": title_sr, "title_en": title_en,
        "description": desc_sr, "description_en": desc_en,
        "recommendation": "", "recommendation_en": "",
    }


def _fail(check_id, severity, title_sr, title_en, desc_sr, desc_en, rec_sr, rec_en):
    return {
        "id": check_id, "category": "API Security", "severity": severity, "passed": False,
        "title": title_sr, "title_en": title_en,
        "description": desc_sr, "description_en": desc_en,
        "recommendation": rec_sr, "recommendation_en": rec_en,
    }


def _get_homepage_body(base_url, session):
    """Fetch homepage body for false-positive detection (SPA routing)."""
    try:
        resp = safe_get(session, base_url, timeout=TIMEOUT)
        return resp.text[:2000]
    except Exception:
        return ""


def run(base_url: str, session: requests.Session) -> List[Dict[str, Any]]:
    results = []
    base = base_url.rstrip("/")
    homepage_body = _get_homepage_body(base_url, session)

    # ── 1. GraphQL Introspection ──────────────────────────────────────
    try:
        resp = safe_post(
            session,
            base + "/graphql",
            json={"query": "{__schema{types{name}}}"},
            headers={"Content-Type": "application/json"},
            timeout=TIMEOUT,
        )
        if resp.status_code == 200 and "__schema" in resp.text:
            results.append(_fail("api_graphql_introspection", "HIGH",
                "GraphQL introspection je omogucen",
                "GraphQL introspection is enabled",
                "GraphQL introspection endpoint (/graphql) otkriva kompletnu shemu API-ja ukljucujuci sve tipove, polja i relacije. Napadac moze mapirati ceo API bez dokumentacije.",
                "GraphQL introspection endpoint (/graphql) exposes the complete API schema including all types, fields and relations. An attacker can map the entire API without documentation.",
                "Onemogucite introspection u produkciji. U Apollo Server: introspection: false. U graphene: middleware za blokiranje.",
                "Disable introspection in production. In Apollo Server: introspection: false. In graphene: use middleware to block."))
        else:
            results.append(_pass("api_graphql_ok",
                "GraphQL introspection nije dostupan",
                "GraphQL introspection is not accessible",
                "GraphQL endpoint ne otkriva shemu putem introspection-a ili nije pronadjen.",
                "GraphQL endpoint does not expose schema via introspection or was not found."))
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
        results.append(_pass("api_graphql_ok",
            "GraphQL endpoint nije pronadjen",
            "GraphQL endpoint not found",
            "GraphQL endpoint (/graphql) nije dostupan na ovom serveru.",
            "GraphQL endpoint (/graphql) is not available on this server."))
    except Exception:
        results.append(_pass("api_graphql_ok",
            "GraphQL endpoint nije pronadjen",
            "GraphQL endpoint not found",
            "GraphQL endpoint (/graphql) nije dostupan na ovom serveru.",
            "GraphQL endpoint (/graphql) is not available on this server."))

    # ── 2. API Endpoint Discovery ─────────────────────────────────────
    api_paths = ["/api/", "/api/v1/", "/api/v2/", "/rest/", "/v1/"]
    discovered_endpoints = []

    for path in api_paths:
        try:
            resp = safe_head(session, base + path, timeout=TIMEOUT)
            if resp.status_code in (200, 301, 302):
                # False positive detection: check if it returns same content as homepage (SPA)
                try:
                    get_resp = safe_get(session, base + path, timeout=TIMEOUT)
                    if homepage_body and get_resp.text[:2000] == homepage_body:
                        continue  # SPA routing, skip
                except Exception:
                    pass
                discovered_endpoints.append(path)
        except Exception:
            pass

    if discovered_endpoints:
        ep_list = ", ".join(discovered_endpoints)
        results.append(_pass("api_endpoints_found",
            f"Pronadjeni API endpointi: {ep_list}",
            f"API endpoints discovered: {ep_list}",
            f"Sledeci API endpointi su dostupni: {ep_list}. Ovo je informativni nalaz.",
            f"The following API endpoints are accessible: {ep_list}. This is an informational finding."))
    else:
        results.append(_pass("api_endpoints_none",
            "Nisu pronadjeni standardni API endpointi",
            "No standard API endpoints found",
            "Nijedan od standardnih API putanja (/api/, /api/v1/, /rest/, itd.) nije pronadjen.",
            "None of the standard API paths (/api/, /api/v1/, /rest/, etc.) were found."))

    # ── 3. Swagger/OpenAPI Exposed ────────────────────────────────────
    swagger_paths = ["/swagger.json", "/openapi.json", "/swagger-ui.html", "/api-docs"]
    exposed_docs = []

    for path in swagger_paths:
        try:
            resp = safe_get(session, base + path, timeout=TIMEOUT)
            if resp.status_code == 200:
                body_lower = resp.text.lower()
                if "swagger" in body_lower or "openapi" in body_lower or '"paths"' in body_lower:
                    # False positive: SPA routing check
                    if homepage_body and resp.text[:2000] == homepage_body:
                        continue
                    exposed_docs.append(path)
        except Exception:
            pass

    if exposed_docs:
        doc_list = ", ".join(exposed_docs)
        results.append(_fail("api_swagger_exposed", "MEDIUM",
            f"API dokumentacija javno dostupna: {doc_list}",
            f"API documentation publicly exposed: {doc_list}",
            f"Swagger/OpenAPI dokumentacija je dostupna na: {doc_list}. Ovo otkriva kompletnu strukturu API-ja, parametre i modele podataka.",
            f"Swagger/OpenAPI documentation is accessible at: {doc_list}. This reveals the complete API structure, parameters and data models.",
            "Uklonite ili zastitite API dokumentaciju u produkciji. Dodajte autentifikaciju ili IP whitelisting.",
            "Remove or protect API documentation in production. Add authentication or IP whitelisting."))
    else:
        results.append(_pass("api_swagger_ok",
            "API dokumentacija nije javno izlozena",
            "API documentation is not publicly exposed",
            "Swagger/OpenAPI dokumentacija nije pronadjena na standardnim putanjama.",
            "Swagger/OpenAPI documentation was not found at standard paths."))

    # ── 4. API Without Auth ───────────────────────────────────────────
    if discovered_endpoints:
        unauth_endpoints = []
        for path in discovered_endpoints:
            try:
                resp = safe_get(session, base + path, timeout=TIMEOUT,
                                headers={"Accept": "application/json"})
                if resp.status_code == 200:
                    content_type = resp.headers.get("Content-Type", "").lower()
                    body = resp.text.strip()
                    # Check if response contains JSON data (not an error response)
                    if "json" in content_type or (body.startswith(("{", "[")) and len(body) > 5):
                        # Check it's not an error/auth-required response
                        body_lower = body.lower()
                        if not any(err in body_lower for err in ['"error"', '"unauthorized"', '"forbidden"', '"message":"auth']):
                            unauth_endpoints.append(path)
            except Exception:
                pass

        if unauth_endpoints:
            ep_list = ", ".join(unauth_endpoints)
            results.append(_fail("api_no_auth", "HIGH",
                f"API endpointi dostupni bez autentifikacije: {ep_list}",
                f"API endpoints accessible without authentication: {ep_list}",
                f"Sledeci API endpointi vracaju podatke bez Authorization header-a: {ep_list}. Neautentifikovani pristup moze otkriti osetljive podatke.",
                f"The following API endpoints return data without an Authorization header: {ep_list}. Unauthenticated access may expose sensitive data.",
                "Dodajte autentifikaciju (JWT, API kljuc, OAuth) na sve API endpointe. Implementirajte middleware za proveru tokena.",
                "Add authentication (JWT, API key, OAuth) to all API endpoints. Implement token verification middleware."))
        else:
            results.append(_pass("api_auth_ok",
                "API endpointi zahtevaju autentifikaciju",
                "API endpoints require authentication",
                "Pronadjeni API endpointi ne vracaju podatke bez autentifikacije.",
                "Discovered API endpoints do not return data without authentication."))
    else:
        results.append(_pass("api_auth_ok",
            "Nema API endpointa za proveru autentifikacije",
            "No API endpoints to check authentication",
            "Nisu pronadjeni API endpointi za testiranje pristupa bez autentifikacije.",
            "No API endpoints were found to test for unauthenticated access."))

    # ── 5. CORS on API ────────────────────────────────────────────────
    if discovered_endpoints:
        cors_issues = []
        for path in discovered_endpoints:
            try:
                resp = safe_get(
                    session,
                    base + path,
                    timeout=TIMEOUT,
                    headers={"Origin": "https://evil-attacker.com"},
                )
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                if "evil-attacker.com" in acao:
                    cors_issues.append((path, "reflected"))
                elif acao == "*":
                    cors_issues.append((path, "wildcard"))
            except Exception:
                pass

        reflected = [p for p, t in cors_issues if t == "reflected"]
        wildcard = [p for p, t in cors_issues if t == "wildcard"]

        if reflected:
            ep_list = ", ".join(reflected)
            results.append(_fail("api_cors_reflected", "HIGH",
                f"API CORS reflektuje proizvoljni Origin: {ep_list}",
                f"API CORS reflects arbitrary Origin: {ep_list}",
                f"API endpointi ({ep_list}) reflektuju bilo koji Origin header u CORS odgovoru. Napadac moze sa svog sajta slati zahteve vasem API-ju u ime korisnika.",
                f"API endpoints ({ep_list}) reflect any Origin header in CORS response. An attacker can send requests to your API from their site on behalf of users.",
                "Implementirajte whitelist dozvoljenih origina. Nikada ne kopirajte Origin header direktno u odgovor.",
                "Implement a whitelist of allowed origins. Never copy the Origin header directly into the response."))
        elif wildcard:
            ep_list = ", ".join(wildcard)
            results.append(_fail("api_cors_wildcard", "MEDIUM",
                f"API CORS dozvoljava sve origine (*): {ep_list}",
                f"API CORS allows all origins (*): {ep_list}",
                f"API endpointi ({ep_list}) imaju Access-Control-Allow-Origin: * sto znaci da bilo koji sajt moze citati odgovore vaseg API-ja.",
                f"API endpoints ({ep_list}) have Access-Control-Allow-Origin: * meaning any site can read your API responses.",
                "Ogranichite CORS na specificne domene umesto wildcard (*). Koristite: Access-Control-Allow-Origin: https://vasajt.com",
                "Restrict CORS to specific domains instead of wildcard (*). Use: Access-Control-Allow-Origin: https://yourdomain.com"))
        else:
            results.append(_pass("api_cors_ok",
                "CORS na API endpointima je pravilno konfigurisan",
                "CORS on API endpoints is properly configured",
                "API endpointi ne dozvoljavaju pristup sa neovlascenih origina.",
                "API endpoints do not allow access from unauthorized origins."))
    else:
        results.append(_pass("api_cors_ok",
            "Nema API endpointa za proveru CORS-a",
            "No API endpoints to check CORS",
            "Nisu pronadjeni API endpointi za testiranje CORS konfiguracije.",
            "No API endpoints were found to test CORS configuration."))

    return results
