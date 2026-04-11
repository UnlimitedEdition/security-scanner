# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Toske-Programer (Web Security Scanner contributors)
"""
.well-known endpoint enumerator (Roadmap #6).

Probes a curated list of IETF/W3C-registered .well-known endpoints
beyond security.txt (which is already covered by extras_check). The
goal is not to flag missing endpoints as vulnerabilities — most sites
legitimately do not use most of these — but to surface which ones
are exposed, because each one reveals platform/capability information
that helps an attacker profile the site.

A few endpoints are specifically privacy/security-relevant:

  - /.well-known/change-password     — RFC 8615 password-change URL hint
                                       (modern password managers look
                                       for this; missing it is a UX
                                       gap, not a security issue).
  - /.well-known/openid-configuration — OIDC discovery document; if
                                        exposed, reveals every claim
                                        and every auth endpoint.
  - /.well-known/host-meta           — XRD / webfinger metadata, leaks
                                       service endpoints.
  - /.well-known/assetlinks.json     — Android App Links linking
                                       package signatures to the domain.
  - /.well-known/apple-app-site-association
                                     — Apple Universal Links, same role.
  - /.well-known/openpgpkey/...      — OpenPGP Web Key Directory keys.
  - /.well-known/webfinger           — social discovery (account lookups).
  - /.well-known/nodeinfo            — Fediverse/ActivityPub server info.

Every probe is a passive HTTP GET. When a JSON-shape endpoint
(assetlinks, apple-app-site-association, openid-configuration,
nodeinfo) responds 200, we parse the top-level to confirm it is real
JSON — otherwise an SPA catch-all HTML that happens to 200 on every
path would produce false positives.
"""
import json
import sys
import os
import concurrent.futures
import requests
from typing import List, Dict, Any, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from security_utils import safe_get, UnsafeTargetError

TIMEOUT = 5
MAX_WORKERS = 5

# (path, shape, description_key)
# shape is "json" for JSON validation or "text" for plain fetch.
_WELLKNOWN_PATHS = [
    ("/.well-known/change-password",             "text",  "change_password"),
    ("/.well-known/assetlinks.json",             "json",  "assetlinks"),
    ("/.well-known/apple-app-site-association",  "json",  "apple_app_site"),
    ("/.well-known/openid-configuration",        "json",  "openid"),
    ("/.well-known/host-meta",                   "text",  "host_meta"),
    ("/.well-known/webfinger",                   "text",  "webfinger"),
    ("/.well-known/nodeinfo",                    "json",  "nodeinfo"),
    ("/.well-known/openpgpkey/hu/policy",        "text",  "openpgpkey"),
]

# Bilingual finding text per endpoint id.
_DESCRIPTIONS: Dict[str, Dict[str, str]] = {
    "change_password": {
        "title_sr": ".well-known/change-password dostupan (RFC 8615)",
        "title_en": ".well-known/change-password is available (RFC 8615)",
        "desc_sr": "Endpoint '/.well-known/change-password' je dostupan i koristi se od strane password manager-a (Chrome, Safari, Bitwarden, 1Password) da bi direktno otvorili stranicu za promenu lozinke korisnika. Ovo je pozitivan UX signal — korisnici mogu brže rotirati kompromitovane lozinke.",
        "desc_en": "The '/.well-known/change-password' endpoint is available and is used by password managers (Chrome, Safari, Bitwarden, 1Password) to open a user's password change page directly. This is a positive UX signal — users can rotate compromised passwords faster.",
    },
    "assetlinks": {
        "title_sr": ".well-known/assetlinks.json dostupan — Android App Links",
        "title_en": ".well-known/assetlinks.json is available — Android App Links",
        "desc_sr": "Endpoint '/.well-known/assetlinks.json' dokazuje vlasništvo domena za Android App Links (vezuje Android aplikaciju sa potpisom paketa za ovaj domen). Sadržaj otkriva koje aplikacije su autorizovane za deep linking.",
        "desc_en": "The '/.well-known/assetlinks.json' endpoint proves domain ownership for Android App Links (binds an Android app's package signature to this domain). The contents reveal which apps are authorized for deep linking.",
    },
    "apple_app_site": {
        "title_sr": ".well-known/apple-app-site-association dostupan — iOS Universal Links",
        "title_en": ".well-known/apple-app-site-association is available — iOS Universal Links",
        "desc_sr": "Endpoint '/.well-known/apple-app-site-association' dokazuje vlasništvo domena za iOS Universal Links. Otkriva Team ID-eve i bundle ID-eve autorizovanih iOS aplikacija.",
        "desc_en": "The '/.well-known/apple-app-site-association' endpoint proves domain ownership for iOS Universal Links. It reveals Team IDs and bundle IDs of authorized iOS apps.",
    },
    "openid": {
        "title_sr": ".well-known/openid-configuration dostupan — OIDC Discovery",
        "title_en": ".well-known/openid-configuration is available — OIDC Discovery",
        "desc_sr": "Endpoint '/.well-known/openid-configuration' je OIDC discovery dokument i detaljno otkriva sve auth endpoint-e (authorize, token, userinfo, jwks, introspect, revocation), podržane claim-ove, grant types, scopes i potpisne algoritme. Ovo je legitimna javno publikovana konfiguracija ali je istovremeno mapa za napadača.",
        "desc_en": "The '/.well-known/openid-configuration' endpoint is an OIDC discovery document and reveals every auth endpoint (authorize, token, userinfo, jwks, introspect, revocation), supported claims, grant types, scopes, and signing algorithms. This is legitimate public configuration but also an attacker's roadmap.",
    },
    "host_meta": {
        "title_sr": ".well-known/host-meta dostupan — XRD metadata",
        "title_en": ".well-known/host-meta is available — XRD metadata",
        "desc_sr": "Endpoint '/.well-known/host-meta' je XRD dokument koji otkriva vezane servise, webfinger endpoint-e i druge metapodatke. Tipično za socijalne platforme i OAuth servere.",
        "desc_en": "The '/.well-known/host-meta' endpoint is an XRD document that reveals linked services, webfinger endpoints, and other metadata. Typical for social platforms and OAuth servers.",
    },
    "webfinger": {
        "title_sr": ".well-known/webfinger dostupan — social discovery",
        "title_en": ".well-known/webfinger is available — social discovery",
        "desc_sr": "Endpoint '/.well-known/webfinger' omogućava lookup korisničkih naloga preko emaila ili domena. Fediverse (Mastodon, Pleroma) i OAuth servere cesto ga koriste. Potencijalni izvor user enumeration-a.",
        "desc_en": "The '/.well-known/webfinger' endpoint allows looking up user accounts by email or domain. Fediverse (Mastodon, Pleroma) and OAuth servers use it often. Potential user enumeration surface.",
    },
    "nodeinfo": {
        "title_sr": ".well-known/nodeinfo dostupan — ActivityPub metadata",
        "title_en": ".well-known/nodeinfo is available — ActivityPub metadata",
        "desc_sr": "Endpoint '/.well-known/nodeinfo' izlaže ActivityPub / Fediverse server info: software name, verzija, broj korisnika, otvorena registracija. Korisno za profiling servera u Fediverse ekosistemu.",
        "desc_en": "The '/.well-known/nodeinfo' endpoint exposes ActivityPub / Fediverse server info: software name, version, user count, open registration status. Useful for profiling servers in the Fediverse ecosystem.",
    },
    "openpgpkey": {
        "title_sr": ".well-known/openpgpkey/... dostupan — Web Key Directory",
        "title_en": ".well-known/openpgpkey/... is available — Web Key Directory",
        "desc_sr": "Endpoint '/.well-known/openpgpkey/' je OpenPGP Web Key Directory koji omogućava automatsko preuzimanje javnih PGP ključeva korisnika na domenu. Pozitivan signal za bezbednu email komunikaciju.",
        "desc_en": "The '/.well-known/openpgpkey/' endpoint is an OpenPGP Web Key Directory that enables automatic retrieval of users' public PGP keys on the domain. A positive signal for secure email communication.",
    },
}


def _probe_wellknown(
    base_url: str,
    session: requests.Session,
    path: str,
    shape: str,
) -> bool:
    """
    Probe a single .well-known endpoint. Returns True when the endpoint
    exists and matches the expected shape (JSON parseable for JSON shape,
    non-HTML for text shape). Returns False on 404, network error, or
    SPA catch-all HTML shell.
    """
    url = base_url.rstrip("/") + path
    try:
        resp = safe_get(session, url, timeout=TIMEOUT, max_redirects=0)
    except (UnsafeTargetError, requests.exceptions.RequestException):
        return False
    except Exception:
        return False

    # change-password typically returns a 302 redirect to the actual
    # password change page, which counts as "present".
    if path == "/.well-known/change-password":
        return resp.status_code in (200, 301, 302, 303, 307, 308)

    if resp.status_code != 200:
        return False

    if shape == "json":
        try:
            data = json.loads(resp.text)
        except Exception:
            return False
        # Must parse as a dict or list, not a bare value
        return isinstance(data, (dict, list))

    # text shape — reject SPA HTML shells
    try:
        body = resp.text.lstrip()[:64].lower()
    except Exception:
        return False
    if body.startswith("<!doctype html") or body.startswith("<html"):
        return False
    return len(resp.content) > 10


def _finding(path_id: str) -> Dict[str, Any]:
    spec = _DESCRIPTIONS[path_id]
    return {
        "id": f"wellknown_{path_id}",
        "category": "Well-Known Endpoints",
        "severity": "INFO",
        "passed": True,
        "title": spec["title_sr"],
        "title_en": spec["title_en"],
        "description": spec["desc_sr"],
        "description_en": spec["desc_en"],
        "recommendation": "",
        "recommendation_en": "",
    }


def run(base_url: str, session: requests.Session) -> List[Dict[str, Any]]:
    """
    Probe eight .well-known endpoints in parallel. Findings are always
    INFO pozitivne — missing endpoints are not flagged because most
    sites legitimately do not use most of these. The value is in
    surfacing which ones ARE exposed, since each one reveals platform
    capabilities useful to both the site owner (confirming their
    configuration works) and an attacker profiling the target.
    """
    results: List[Dict[str, Any]] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(_probe_wellknown, base_url, session, path, shape): path_id
            for path, shape, path_id in _WELLKNOWN_PATHS
        }
        for future in concurrent.futures.as_completed(futures):
            path_id = futures[future]
            try:
                present = future.result(timeout=TIMEOUT + 2)
            except Exception:
                continue
            if present:
                results.append(_finding(path_id))

    return results
