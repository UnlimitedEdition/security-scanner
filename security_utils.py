"""
Security Utilities — Centralized SSRF protection and safe HTTP wrappers.

Every outbound request made on behalf of a user MUST go through safe_get().
This is the scanner's own defense layer — without it, a malicious target
could redirect the scanner to internal services (localhost, AWS metadata,
Redis, databases, etc.) and exfiltrate or mutate internal state.
"""
import ipaddress
import socket
from urllib.parse import urlparse, urljoin
from typing import Tuple, Optional

import requests


# Absolute cap on redirect chain length (prevents redirect loops + DoS)
MAX_REDIRECTS = 5

# Only these URL schemes are allowed as scan targets
ALLOWED_SCHEMES = {"http", "https"}

# Hostnames that must never be contacted, even before DNS resolution
FORBIDDEN_HOSTNAMES = {
    "localhost",
    "ip6-localhost",
    "ip6-loopback",
    "broadcasthost",
}

# Hostname suffixes that indicate internal/private networks
FORBIDDEN_SUFFIXES = (
    ".localhost",
    ".local",
    ".lan",
    ".intranet",
    ".internal",
    ".corp",
    ".home",
    ".private",
)

# IPv4 ranges that are never safe to contact from a scanner
_V4_FORBIDDEN_NETS = [
    ipaddress.ip_network(n) for n in (
        "0.0.0.0/8",          # "This network"
        "10.0.0.0/8",          # Private
        "100.64.0.0/10",       # Carrier-grade NAT
        "127.0.0.0/8",         # Loopback
        "169.254.0.0/16",      # Link-local (AWS/GCP metadata!)
        "172.16.0.0/12",       # Private
        "192.0.0.0/24",        # IETF Protocol Assignments
        "192.0.2.0/24",        # TEST-NET-1
        "192.168.0.0/16",      # Private
        "198.18.0.0/15",       # Benchmark
        "198.51.100.0/24",     # TEST-NET-2
        "203.0.113.0/24",      # TEST-NET-3
        "224.0.0.0/4",         # Multicast
        "240.0.0.0/4",         # Reserved
        "255.255.255.255/32",  # Broadcast
    )
]

# IPv6 ranges that are never safe to contact
_V6_FORBIDDEN_NETS = [
    ipaddress.ip_network(n) for n in (
        "::/128",          # Unspecified
        "::1/128",         # Loopback
        "::ffff:0:0/96",   # IPv4-mapped (handled specially below)
        "64:ff9b::/96",    # IPv4/IPv6 translation
        "100::/64",        # Discard-Only
        "2001:db8::/32",   # Documentation
        "fc00::/7",        # Unique local
        "fe80::/10",       # Link-local
        "ff00::/8",        # Multicast
    )
]


class UnsafeTargetError(ValueError):
    """Raised when a URL points to a forbidden address (SSRF attempt)."""
    pass


def _is_forbidden_ip(ip_str: str) -> bool:
    """Return True if the given IP literal points to a private/reserved range."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        # Unparseable — treat as forbidden rather than silently pass
        return True

    # Python's built-in properties cover most cases on modern versions,
    # but we re-check against explicit networks for defense in depth
    # (older Python versions miss some ranges like CGNAT).
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return True

    if isinstance(ip, ipaddress.IPv4Address):
        for net in _V4_FORBIDDEN_NETS:
            if ip in net:
                return True
        return False

    # IPv6
    # IPv4-mapped IPv6 (::ffff:127.0.0.1) — unwrap and recheck the IPv4
    mapped = ip.ipv4_mapped
    if mapped is not None:
        return _is_forbidden_ip(str(mapped))

    for net in _V6_FORBIDDEN_NETS:
        if ip in net:
            return True
    return False


def _resolve_all_ips(hostname: str) -> list:
    """Return all IP addresses (v4 + v6) a hostname resolves to, deduplicated."""
    try:
        infos = socket.getaddrinfo(hostname, None)
    except (socket.gaierror, socket.herror, UnicodeError):
        return []
    return list({info[4][0] for info in infos})


def is_safe_target(url: str) -> Tuple[bool, str]:
    """
    Validate that a URL is safe to fetch from the scanner.

    Performs DNS resolution and checks every resolved IP against the forbidden
    list to prevent DNS-based bypass attacks. Returns (is_safe, reason).
    """
    if not url or not isinstance(url, str):
        return False, "Empty or invalid URL"

    try:
        parsed = urlparse(url)
    except Exception:
        return False, "Cannot parse URL"

    scheme = (parsed.scheme or "").lower()
    if scheme not in ALLOWED_SCHEMES:
        return False, f"Scheme '{scheme}' not allowed (only http/https)"

    hostname = parsed.hostname
    if not hostname:
        return False, "Missing hostname"

    hostname_lower = hostname.lower().rstrip(".")

    if hostname_lower in FORBIDDEN_HOSTNAMES:
        return False, f"Hostname '{hostname}' is forbidden"

    for suffix in FORBIDDEN_SUFFIXES:
        if hostname_lower.endswith(suffix):
            return False, f"Hostname suffix '{suffix}' indicates internal network"

    # If the hostname itself is an IP literal, validate it directly
    try:
        literal_ip = ipaddress.ip_address(hostname_lower)
        if _is_forbidden_ip(str(literal_ip)):
            return False, f"IP {literal_ip} is private/reserved"
        return True, ""
    except ValueError:
        pass  # Not an IP literal — proceed to DNS

    # DNS resolve. ALL answers must be public — stops DNS rebinding tricks
    # where a hostname resolves to a mix of public + internal addresses.
    ips = _resolve_all_ips(hostname_lower)
    if not ips:
        return False, f"Cannot resolve hostname '{hostname}'"

    for ip_str in ips:
        if _is_forbidden_ip(ip_str):
            return False, (
                f"Hostname '{hostname}' resolves to forbidden IP {ip_str}"
            )

    return True, ""


def assert_safe_target(url: str) -> None:
    """Raise UnsafeTargetError if the URL is not safe to fetch."""
    safe, reason = is_safe_target(url)
    if not safe:
        raise UnsafeTargetError(reason)


def safe_get(
    session: requests.Session,
    url: str,
    *,
    timeout: int = 10,
    max_redirects: int = MAX_REDIRECTS,
    **kwargs,
) -> requests.Response:
    """
    Safe replacement for session.get() — enforces SSRF protection on every
    redirect hop, not just the initial URL.

    The key difference from requests' default behavior: redirects are followed
    MANUALLY, and each new URL is re-validated against is_safe_target() before
    the next request is issued. This blocks the classic SSRF bypass where an
    attacker-controlled public host responds with `302 Location: http://127.0.0.1/`.

    Pass max_redirects=0 to disable redirect following entirely (equivalent to
    allow_redirects=False on the stdlib).
    """
    # Strip any caller-supplied allow_redirects — we manage it ourselves
    kwargs.pop("allow_redirects", None)

    current_url = url
    history = []  # Track intermediate redirect responses, like requests does

    while True:
        assert_safe_target(current_url)

        resp = session.get(
            current_url,
            timeout=timeout,
            allow_redirects=False,
            **kwargs,
        )

        # Caller opted out of redirect following — return whatever we got
        if max_redirects == 0:
            return resp

        if resp.status_code not in (301, 302, 303, 307, 308):
            # Final hop — attach the collected history so callers like
            # redirect_check can inspect the chain via resp.history
            resp.history = history
            return resp

        location = resp.headers.get("Location")
        if not location:
            resp.history = history
            return resp

        if len(history) >= max_redirects:
            raise requests.exceptions.TooManyRedirects(
                f"Exceeded {max_redirects} redirects starting from {url}"
            )

        history.append(resp)
        current_url = urljoin(current_url, location)


def safe_head(
    session: requests.Session,
    url: str,
    *,
    timeout: int = 10,
    **kwargs,
) -> requests.Response:
    """HEAD variant — single hop only, no redirect following."""
    assert_safe_target(url)
    kwargs.pop("allow_redirects", None)
    return session.head(url, timeout=timeout, allow_redirects=False, **kwargs)


def safe_post(
    session: requests.Session,
    url: str,
    *,
    timeout: int = 10,
    **kwargs,
) -> requests.Response:
    """
    POST variant — single hop only, no redirect following.
    POST requests should never follow redirects across hosts for SSRF safety,
    so we validate the target and then issue exactly one POST.
    """
    assert_safe_target(url)
    kwargs.pop("allow_redirects", None)
    return session.post(url, timeout=timeout, allow_redirects=False, **kwargs)
