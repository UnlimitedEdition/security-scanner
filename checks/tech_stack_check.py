# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Toske-Programer (Web Security Scanner contributors)
"""
Technology Stack Detection
Deep analysis of technologies used on the website.
Detects frameworks, CDNs, analytics, hosting providers.
"""
import re
from typing import List, Dict, Any


# Technology signatures: (pattern_in_html_or_headers, tech_name, category)
TECH_SIGNATURES = [
    # Frameworks
    (r'<meta\s+name=["\']generator["\']\s+content=["\']WordPress', "WordPress", "CMS"),
    (r'<meta\s+name=["\']generator["\']\s+content=["\']Joomla', "Joomla", "CMS"),
    (r'<meta\s+name=["\']generator["\']\s+content=["\']Drupal', "Drupal", "CMS"),
    (r'wp-content/', "WordPress", "CMS"),
    (r'__next', "Next.js", "Framework"),
    (r'__nuxt', "Nuxt.js", "Framework"),
    (r'ng-version', "Angular", "Framework"),
    (r'data-reactroot', "React", "Framework"),
    (r'data-v-[a-f0-9]', "Vue.js", "Framework"),
    (r'svelte', "Svelte", "Framework"),
    (r'gatsby', "Gatsby", "Framework"),
    (r'astro', "Astro", "Framework"),
    (r'_app\.js.*vercel', "Vercel", "Hosting"),
    (r'netlify', "Netlify", "Hosting"),
    # JS Libraries
    (r'jquery[.-/](\d+\.\d+)', "jQuery", "Library"),
    (r'bootstrap[.-/](\d+\.\d+)', "Bootstrap", "Library"),
    (r'tailwindcss', "Tailwind CSS", "Library"),
    (r'font-awesome', "Font Awesome", "Library"),
    (r'alpinejs', "Alpine.js", "Library"),
    (r'htmx', "HTMX", "Library"),
    # Analytics
    (r'google-analytics\.com|gtag|googletagmanager', "Google Analytics", "Analytics"),
    (r'facebook\.net.*fbevents|fbq\(', "Facebook Pixel", "Analytics"),
    (r'hotjar\.com', "Hotjar", "Analytics"),
    (r'clarity\.ms', "Microsoft Clarity", "Analytics"),
    (r'plausible\.io', "Plausible", "Analytics"),
    (r'matomo', "Matomo", "Analytics"),
    (r'yandex.*metrika|mc\.yandex', "Yandex Metrica", "Analytics"),
    # CDN
    (r'cloudflare', "Cloudflare", "CDN"),
    (r'cdn\.jsdelivr', "jsDelivr", "CDN"),
    (r'cdnjs\.cloudflare', "cdnjs", "CDN"),
    (r'unpkg\.com', "unpkg", "CDN"),
    (r'fastly', "Fastly", "CDN"),
    (r'akamai', "Akamai", "CDN"),
    (r'cloudfront\.net', "AWS CloudFront", "CDN"),
    # Payment
    (r'stripe\.com|stripe\.js', "Stripe", "Payment"),
    (r'paypal\.com', "PayPal", "Payment"),
    # Chat/Support
    (r'intercom', "Intercom", "Chat"),
    (r'tawk\.to', "Tawk.to", "Chat"),
    (r'crisp\.chat', "Crisp", "Chat"),
    (r'zendesk', "Zendesk", "Support"),
    # Email
    (r'mailchimp', "Mailchimp", "Email"),
    (r'sendgrid', "SendGrid", "Email"),
]

HEADER_SIGNATURES = [
    ("server", "nginx", "Nginx", "Server"),
    ("server", "apache", "Apache", "Server"),
    ("server", "cloudflare", "Cloudflare", "CDN/Server"),
    ("server", "vercel", "Vercel", "Hosting"),
    ("server", "netlify", "Netlify", "Hosting"),
    ("server", "github.com", "GitHub Pages", "Hosting"),
    ("x-powered-by", "php", "PHP", "Language"),
    ("x-powered-by", "asp.net", "ASP.NET", "Language"),
    ("x-powered-by", "express", "Express.js", "Framework"),
    ("x-powered-by", "next.js", "Next.js", "Framework"),
]


def run(response_body: str, response_headers: dict) -> List[Dict[str, Any]]:
    results = []

    detected = {}  # name -> category

    # Scan HTML body
    body_lower = response_body.lower() if response_body else ""
    for pattern, tech_name, category in TECH_SIGNATURES:
        if re.search(pattern, body_lower, re.IGNORECASE):
            if tech_name not in detected:
                detected[tech_name] = category

    # Scan headers
    lower_headers = {k.lower(): v.lower() for k, v in response_headers.items()}
    for header_name, signature, tech_name, category in HEADER_SIGNATURES:
        header_val = lower_headers.get(header_name, "")
        if signature in header_val:
            if tech_name not in detected:
                detected[tech_name] = category

    if detected:
        # Group by category
        groups = {}
        for tech, cat in detected.items():
            if cat not in groups:
                groups[cat] = []
            groups[cat].append(tech)

        tech_list_sr = []
        tech_list_en = []
        for cat, techs in sorted(groups.items()):
            tech_list_sr.append(f"{cat}: {', '.join(techs)}")
            tech_list_en.append(f"{cat}: {', '.join(techs)}")

        results.append({
            "id": "tech_stack_detected",
            "category": "Technology Stack",
            "severity": "INFO",
            "passed": True,
            "title": f"Detektovano {len(detected)} tehnologija",
            "title_en": f"Detected {len(detected)} technologies",
            "description": " | ".join(tech_list_sr),
            "description_en": " | ".join(tech_list_en),
            "recommendation": "",
            "recommendation_en": "",
        })

        # Flag analytics without consent
        analytics = [t for t, c in detected.items() if c == "Analytics"]
        if analytics:
            results.append({
                "id": "tech_analytics_found",
                "category": "Technology Stack",
                "severity": "INFO",
                "passed": True,
                "title": f"Analitika: {', '.join(analytics)}",
                "title_en": f"Analytics: {', '.join(analytics)}",
                "description": f"Pronadjeno {len(analytics)} analitika servisa. Proverite GDPR tab za consent status.",
                "description_en": f"Found {len(analytics)} analytics services. Check GDPR tab for consent status.",
                "recommendation": "",
                "recommendation_en": "",
            })
    else:
        results.append({
            "id": "tech_stack_none",
            "category": "Technology Stack",
            "severity": "INFO",
            "passed": True,
            "title": "Tehnologije nisu detektovane",
            "title_en": "No technologies detected",
            "description": "Nije moguce detektovati tehnoloski stek iz HTML-a i headera.",
            "description_en": "Could not detect technology stack from HTML and headers.",
            "recommendation": "",
            "recommendation_en": "",
        })

    return results
