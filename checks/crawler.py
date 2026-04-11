# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Toske-Programer (Web Security Scanner contributors)
"""
Site Crawler
Follows links from the homepage to discover pages for multi-page scanning.
Returns a list of unique same-domain URLs (max depth 2, max 20 URLs).
"""
import re
import sys
import os
import requests
from urllib.parse import urlparse, urljoin
from typing import List, Set

# Import from parent directory
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from security_utils import safe_get, UnsafeTargetError

MAX_DEPTH = 2
MAX_URLS = 20
TIMEOUT = 7

SKIP_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp", ".avif",
    ".pdf", ".zip", ".rar", ".gz", ".tar",
    ".css", ".js", ".woff", ".woff2", ".ttf", ".eot",
    ".mp3", ".mp4", ".avi", ".mov", ".webm",
    ".ico", ".xml", ".json", ".txt",
}

SKIP_PATTERNS = [
    "#", "mailto:", "tel:", "javascript:", "data:",
    "/wp-admin", "/wp-login", "/feed", "/rss",
    "?replytocom=", "?share=", "/tag/", "/author/",
]


def _should_skip(url):
    url_lower = url.lower()
    for pattern in SKIP_PATTERNS:
        if pattern in url_lower:
            return True
    parsed = urlparse(url_lower)
    path = parsed.path
    for ext in SKIP_EXTENSIONS:
        if path.endswith(ext):
            return True
    return False


def _extract_links(html, base_url, target_domain):
    links = set()
    # Find all href attributes
    hrefs = re.findall(r'<a\s+[^>]*href=["\']([^"\'#]+)["\']', html, re.IGNORECASE)
    for href in hrefs:
        href = href.strip()
        if not href or _should_skip(href):
            continue
        # Resolve relative URLs
        full_url = urljoin(base_url, href)
        parsed = urlparse(full_url)
        # Only same domain
        if parsed.netloc != target_domain:
            continue
        # Normalize: remove fragment, keep path
        clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if clean.endswith("/"):
            clean = clean[:-1]
        if not clean:
            continue
        links.add(clean)
    return links


def crawl(base_url, session, response_body="", limit=MAX_URLS):
    """
    Crawl the site starting from base_url.
    Returns list of discovered URLs (including base_url).

    The `limit` parameter caps the number of returned URLs. Callers use
    it to match the Pro plan page budget: free tier asks for 1 (homepage
    only, so the crawl is still done for 'pages_found' telemetry), and
    Pro tier asks for up to 10. The hard upper bound is MAX_URLS (20)
    regardless of what the caller requests, so a misconfigured caller
    cannot trigger unbounded crawling.
    """
    # Cap at MAX_URLS even if caller asks for more
    effective_limit = min(max(1, int(limit or 1)), MAX_URLS)

    parsed = urlparse(base_url)
    target_domain = parsed.netloc
    base_clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip("/")

    visited = set()
    visited.add(base_clean)
    to_visit = []

    # Extract links from already-fetched homepage
    if response_body:
        homepage_links = _extract_links(response_body, base_url, target_domain)
        for link in homepage_links:
            if link not in visited and len(visited) + len(to_visit) < effective_limit:
                to_visit.append((link, 1))

    # BFS crawl
    results = [base_clean]

    while to_visit and len(results) < effective_limit:
        url, depth = to_visit.pop(0)
        if url in visited:
            continue
        visited.add(url)

        try:
            # safe_get re-validates every redirect hop against the SSRF
            # blacklist; an attacker cannot use a redirect to reach internal
            # services even if they control the page we're crawling.
            resp = safe_get(session, url, timeout=TIMEOUT)
            if resp.status_code != 200:
                continue
            content_type = resp.headers.get("content-type", "")
            if "text/html" not in content_type:
                continue

            results.append(url)

            # Extract links for next depth level
            if depth < MAX_DEPTH:
                page_links = _extract_links(resp.text[:30000], url, target_domain)
                for link in page_links:
                    if link not in visited and len(to_visit) < effective_limit * 2:
                        to_visit.append((link, depth + 1))

        except UnsafeTargetError:
            # Link pointed somewhere forbidden (e.g. post-redirect to localhost).
            # Silently skip — the URL is just not crawlable from our side.
            continue
        except Exception:
            continue

    return results[:effective_limit]
