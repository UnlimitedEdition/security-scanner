"""
Site Crawler
Follows links from the homepage to discover pages for multi-page scanning.
Returns a list of unique same-domain URLs (max depth 2, max 20 URLs).
"""
import re
import requests
from urllib.parse import urlparse, urljoin
from typing import List, Set

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


def crawl(base_url, session, response_body=""):
    """
    Crawl the site starting from base_url.
    Returns list of discovered URLs (including base_url).
    """
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
            if link not in visited and len(visited) + len(to_visit) < MAX_URLS:
                to_visit.append((link, 1))

    # BFS crawl
    results = [base_clean]

    while to_visit and len(results) < MAX_URLS:
        url, depth = to_visit.pop(0)
        if url in visited:
            continue
        visited.add(url)

        try:
            resp = session.get(url, timeout=TIMEOUT, allow_redirects=True)
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
                    if link not in visited and len(to_visit) < MAX_URLS * 2:
                        to_visit.append((link, depth + 1))

        except Exception:
            continue

    return results[:MAX_URLS]
