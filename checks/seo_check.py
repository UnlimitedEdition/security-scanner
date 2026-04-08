"""
SEO Analysis Check
Checks: meta tags, headings, images, sitemap, robots, canonical, structured data, Open Graph
"""
import re
import requests
from urllib.parse import urlparse
from typing import List, Dict, Any

TIMEOUT = 8


def run(base_url: str, response_body: str, response_headers: dict, session: requests.Session) -> List[Dict[str, Any]]:
    results = []
    domain = urlparse(base_url).netloc

    results.extend(_check_title(response_body))
    results.extend(_check_meta_description(response_body))
    results.extend(_check_meta_viewport(response_body))
    results.extend(_check_canonical(response_body, base_url))
    results.extend(_check_headings(response_body))
    results.extend(_check_images(response_body))
    results.extend(_check_open_graph(response_body))
    results.extend(_check_twitter_cards(response_body))
    results.extend(_check_lang_attr(response_body))
    results.extend(_check_sitemap(base_url, session))
    results.extend(_check_robots_seo(base_url, session))
    results.extend(_check_structured_data(response_body))

    return results


def _check_title(body):
    results = []
    match = re.search(r'<title[^>]*>(.*?)</title>', body, re.IGNORECASE | re.DOTALL)
    if match:
        title = match.group(1).strip()
        length = len(title)
        if length == 0:
            results.append(_fail("seo_title_empty", "MEDIUM",
                "Title tag je prazan",
                "Title tag is empty",
                "Stranica ima <title> tag ali je prazan. Ovo je lose za SEO i deljenje na drustvenim mrezama.",
                "Page has a <title> tag but it is empty. This is bad for SEO and social sharing.",
                "Dodajte opisni naslov od 30-60 karaktera.",
                "Add a descriptive title of 30-60 characters."))
        elif length < 20:
            results.append(_fail("seo_title_short", "LOW",
                f"Title tag je prekratak ({length} karaktera)",
                f"Title tag is too short ({length} characters)",
                f"Naslov: \"{title}\" — preporucena duzina je 30-60 karaktera za optimalan prikaz u pretrazi.",
                f"Title: \"{title}\" — recommended length is 30-60 characters for optimal search display.",
                "Prosiriti naslov da bude 30-60 karaktera sa kljucnim recima.",
                "Extend the title to 30-60 characters with keywords."))
        elif length > 70:
            results.append(_fail("seo_title_long", "LOW",
                f"Title tag je predugacak ({length} karaktera)",
                f"Title tag is too long ({length} characters)",
                f"Google odseca naslove duze od ~60 karaktera u rezultatima pretrage.",
                f"Google truncates titles longer than ~60 characters in search results.",
                "Skratite naslov na 30-60 karaktera.",
                "Shorten the title to 30-60 characters."))
        else:
            results.append(_pass("seo_title_ok",
                f"Title tag prisutan i optimalne duzine ({length} kar.)",
                f"Title tag present and optimal length ({length} chars)",
                f"Naslov: \"{title[:60]}\"",
                f"Title: \"{title[:60]}\""))
    else:
        results.append(_fail("seo_title_missing", "HIGH",
            "Title tag nedostaje",
            "Title tag is missing",
            "Stranica nema <title> tag. Ovo je kriticno za SEO — Google koristi naslov kao glavni faktor rangiranja.",
            "Page has no <title> tag. This is critical for SEO — Google uses the title as a primary ranking factor.",
            "Dodajte <title> tag u <head> sekciju stranice.",
            "Add a <title> tag to the <head> section of the page."))
    return results


def _check_meta_description(body):
    results = []
    match = re.search(r'<meta\s+name=["\']description["\']\s+content=["\']([^"\']*)["\']', body, re.IGNORECASE)
    if not match:
        match = re.search(r'<meta\s+content=["\']([^"\']*?)["\']\s+name=["\']description["\']', body, re.IGNORECASE)
    if match:
        desc = match.group(1).strip()
        length = len(desc)
        if length == 0:
            results.append(_fail("seo_desc_empty", "MEDIUM",
                "Meta description je prazan",
                "Meta description is empty",
                "Meta description tag postoji ali je prazan.",
                "Meta description tag exists but is empty.",
                "Dodajte opis od 120-160 karaktera sa kljucnim recima.",
                "Add a description of 120-160 characters with keywords."))
        elif length < 70:
            results.append(_fail("seo_desc_short", "LOW",
                f"Meta description je prekratak ({length} kar.)",
                f"Meta description is too short ({length} chars)",
                f"Opis: \"{desc}\" — preporucena duzina je 120-160 karaktera.",
                f"Description: \"{desc}\" — recommended length is 120-160 characters.",
                "Prosiriti opis na 120-160 karaktera.",
                "Extend description to 120-160 characters."))
        elif length > 170:
            results.append(_fail("seo_desc_long", "LOW",
                f"Meta description je predugacak ({length} kar.)",
                f"Meta description is too long ({length} chars)",
                "Google odseca opise duze od ~160 karaktera.",
                "Google truncates descriptions longer than ~160 characters.",
                "Skratite opis na 120-160 karaktera.",
                "Shorten description to 120-160 characters."))
        else:
            results.append(_pass("seo_desc_ok",
                f"Meta description prisutan i optimalan ({length} kar.)",
                f"Meta description present and optimal ({length} chars)",
                desc[:100], desc[:100]))
    else:
        results.append(_fail("seo_desc_missing", "MEDIUM",
            "Meta description nedostaje",
            "Meta description is missing",
            "Stranica nema meta description. Google prikazuje opis u rezultatima pretrage — bez njega, bira random tekst sa stranice.",
            "Page has no meta description. Google shows the description in search results — without it, random text is picked.",
            "Dodajte: <meta name=\"description\" content=\"Vas opis od 120-160 karaktera\">",
            "Add: <meta name=\"description\" content=\"Your 120-160 character description\">"))
    return results


def _check_meta_viewport(body):
    results = []
    if re.search(r'<meta\s+name=["\']viewport["\']', body, re.IGNORECASE):
        results.append(_pass("seo_viewport_ok",
            "Viewport meta tag prisutan (mobile-friendly)",
            "Viewport meta tag present (mobile-friendly)",
            "Sajt je konfigurisan za mobilne uredjaje.",
            "Site is configured for mobile devices."))
    else:
        results.append(_fail("seo_viewport_missing", "HIGH",
            "Viewport meta tag nedostaje — sajt nije mobile-friendly",
            "Viewport meta tag missing — site is not mobile-friendly",
            "Bez viewport meta taga, sajt se prikazuje kao desktop verzija na mobilnom. Google penalizuje sajtove koji nisu mobile-friendly.",
            "Without viewport meta tag, the site displays as desktop on mobile. Google penalizes non-mobile-friendly sites.",
            "Dodajte: <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">",
            "Add: <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">"))
    return results


def _check_canonical(body, base_url):
    results = []
    match = re.search(r'<link\s+rel=["\']canonical["\']\s+href=["\']([^"\']+)["\']', body, re.IGNORECASE)
    if not match:
        match = re.search(r'<link\s+href=["\']([^"\']+?)["\']\s+rel=["\']canonical["\']', body, re.IGNORECASE)
    if match:
        results.append(_pass("seo_canonical_ok",
            "Canonical URL definisan",
            "Canonical URL defined",
            f"Canonical: {match.group(1)[:80]}",
            f"Canonical: {match.group(1)[:80]}"))
    else:
        results.append(_fail("seo_canonical_missing", "MEDIUM",
            "Canonical URL nedostaje",
            "Canonical URL is missing",
            "Bez canonical taga, Google moze indeksirati dupliran sadrzaj (http/https, www/non-www varijante).",
            "Without a canonical tag, Google may index duplicate content (http/https, www/non-www variants).",
            "Dodajte: <link rel=\"canonical\" href=\"https://vasajt.com/\">",
            "Add: <link rel=\"canonical\" href=\"https://yoursite.com/\">"))
    return results


def _check_headings(body):
    results = []
    h1_matches = re.findall(r'<h1[^>]*>(.*?)</h1>', body, re.IGNORECASE | re.DOTALL)
    h1_count = len(h1_matches)

    if h1_count == 0:
        results.append(_fail("seo_h1_missing", "HIGH",
            "H1 naslov nedostaje",
            "H1 heading is missing",
            "Stranica nema H1 naslov. H1 je najvazniji heading za SEO — govori Google-u o cemu je stranica.",
            "Page has no H1 heading. H1 is the most important heading for SEO — tells Google what the page is about.",
            "Dodajte jedan H1 naslov sa glavnom temom stranice.",
            "Add one H1 heading with the page's main topic."))
    elif h1_count > 1:
        results.append(_fail("seo_h1_multiple", "LOW",
            f"Vise H1 naslova na stranici ({h1_count})",
            f"Multiple H1 headings on page ({h1_count})",
            "Preporuka je jedan H1 po stranici za jasnu strukturu.",
            "Recommendation is one H1 per page for clear structure.",
            "Zadrzite samo jedan H1 naslov, ostale pretvorite u H2.",
            "Keep only one H1 heading, convert others to H2."))
    else:
        h1_text = re.sub(r'<[^>]+>', '', h1_matches[0]).strip()
        results.append(_pass("seo_h1_ok",
            "H1 naslov prisutan",
            "H1 heading present",
            f"H1: \"{h1_text[:60]}\"",
            f"H1: \"{h1_text[:60]}\""))
    return results


def _check_images(body):
    results = []
    img_tags = re.findall(r'<img\s+[^>]*?>', body, re.IGNORECASE)
    if not img_tags:
        return results

    without_alt = 0
    for img in img_tags:
        if 'alt=' not in img.lower():
            without_alt += 1
        else:
            alt_match = re.search(r'alt=["\'](["\'])', img, re.IGNORECASE)
            if alt_match:
                without_alt += 1

    if without_alt > 0:
        results.append(_fail("seo_img_no_alt", "MEDIUM",
            f"{without_alt} slika bez alt atributa (od {len(img_tags)})",
            f"{without_alt} images without alt attribute (of {len(img_tags)})",
            "Slike bez alt teksta su lose za SEO i pristupacnost. Google koristi alt tekst za razumevanje slika.",
            "Images without alt text are bad for SEO and accessibility. Google uses alt text to understand images.",
            "Dodajte opisni alt atribut svakoj slici: <img src=\"...\" alt=\"Opis slike\">",
            "Add descriptive alt attribute to each image: <img src=\"...\" alt=\"Image description\">"))
    else:
        results.append(_pass("seo_img_alt_ok",
            f"Sve slike imaju alt atribut ({len(img_tags)} slika)",
            f"All images have alt attribute ({len(img_tags)} images)",
            "Slike su pristupacne i optimizovane za SEO.",
            "Images are accessible and optimized for SEO."))
    return results


def _check_open_graph(body):
    results = []
    og_tags = re.findall(r'<meta\s+(?:property|name)=["\']og:([^"\']+)["\']\s+content=["\']([^"\']*)["\']', body, re.IGNORECASE)
    if not og_tags:
        og_tags = re.findall(r'<meta\s+content=["\']([^"\']*?)["\']\s+(?:property|name)=["\']og:([^"\']+)["\']', body, re.IGNORECASE)

    og_keys = [t[0].lower() for t in og_tags] if og_tags else []

    required = ["title", "description", "image"]
    missing = [r for r in required if r not in og_keys]

    if not og_tags:
        results.append(_fail("seo_og_missing", "MEDIUM",
            "Open Graph meta tagovi nedostaju",
            "Open Graph meta tags are missing",
            "Bez OG tagova, Facebook/LinkedIn/Twitter prikazuju los preview kad se deli link vaseg sajta.",
            "Without OG tags, Facebook/LinkedIn/Twitter show poor previews when sharing your site link.",
            "Dodajte og:title, og:description, og:image meta tagove.",
            "Add og:title, og:description, og:image meta tags."))
    elif missing:
        results.append(_fail("seo_og_incomplete", "LOW",
            f"Open Graph: nedostaju {', '.join('og:' + m for m in missing)}",
            f"Open Graph: missing {', '.join('og:' + m for m in missing)}",
            f"Pronadjeno {len(og_keys)} OG tagova ali nedostaju: {', '.join(missing)}.",
            f"Found {len(og_keys)} OG tags but missing: {', '.join(missing)}.",
            f"Dodajte nedostajuce OG tagove: {', '.join('og:' + m for m in missing)}.",
            f"Add missing OG tags: {', '.join('og:' + m for m in missing)}."))
    else:
        results.append(_pass("seo_og_ok",
            f"Open Graph tagovi kompletni ({len(og_keys)} tagova)",
            f"Open Graph tags complete ({len(og_keys)} tags)",
            "Sajt ce imati dobar preview na drustvenim mrezama.",
            "Site will have good previews on social media."))
    return results


def _check_twitter_cards(body):
    results = []
    tc = re.findall(r'<meta\s+(?:name|property)=["\']twitter:([^"\']+)["\']', body, re.IGNORECASE)
    if not tc:
        tc = re.findall(r'<meta\s+content=["\'][^"\']*["\']\s+(?:name|property)=["\']twitter:([^"\']+)["\']', body, re.IGNORECASE)

    if tc:
        results.append(_pass("seo_twitter_ok",
            f"Twitter Card tagovi prisutni ({len(tc)} tagova)",
            f"Twitter Card tags present ({len(tc)} tags)",
            "Sajt ima Twitter Card konfiguraciju za deljenje.",
            "Site has Twitter Card configuration for sharing."))
    else:
        results.append(_fail("seo_twitter_missing", "LOW",
            "Twitter Card tagovi nedostaju",
            "Twitter Card tags are missing",
            "Bez twitter:card i twitter:title tagova, X (Twitter) prikazuje los preview vaseg linka.",
            "Without twitter:card and twitter:title tags, X (Twitter) shows poor preview of your link.",
            "Dodajte: <meta name=\"twitter:card\" content=\"summary_large_image\">",
            "Add: <meta name=\"twitter:card\" content=\"summary_large_image\">"))
    return results


def _check_lang_attr(body):
    results = []
    match = re.search(r'<html[^>]*\slang=["\']([^"\']+)["\']', body, re.IGNORECASE)
    if match:
        results.append(_pass("seo_lang_ok",
            f"HTML lang atribut definisan ({match.group(1)})",
            f"HTML lang attribute defined ({match.group(1)})",
            "Pretrazivaci znaju koji je jezik stranice.",
            "Search engines know the page language."))
    else:
        results.append(_fail("seo_lang_missing", "MEDIUM",
            "HTML lang atribut nedostaje",
            "HTML lang attribute is missing",
            "Bez lang atributa, pretrazivaci ne znaju jezik stranice. Ovo utice na rangiranje u lokalizovanim pretragama.",
            "Without lang attribute, search engines don't know the page language. This affects ranking in localized searches.",
            "Dodajte: <html lang=\"sr\"> (ili odgovarajuci jezicki kod).",
            "Add: <html lang=\"en\"> (or appropriate language code)."))
    return results


def _check_sitemap(base_url, session):
    results = []
    sitemap_urls = [
        base_url.rstrip("/") + "/sitemap.xml",
        base_url.rstrip("/") + "/sitemap_index.xml",
    ]
    found = False
    for url in sitemap_urls:
        try:
            resp = session.get(url, timeout=TIMEOUT, allow_redirects=True)
            if resp.status_code == 200 and ("<?xml" in resp.text[:100] or "<urlset" in resp.text[:500] or "<sitemapindex" in resp.text[:500]):
                found = True
                break
        except Exception:
            pass

    if found:
        results.append(_pass("seo_sitemap_ok",
            "Sitemap.xml pronadjen",
            "Sitemap.xml found",
            "Pretrazivaci mogu efikasno da indeksiraju sve stranice.",
            "Search engines can efficiently index all pages."))
    else:
        results.append(_fail("seo_sitemap_missing", "MEDIUM",
            "Sitemap.xml nedostaje",
            "Sitemap.xml is missing",
            "Bez sitemap-a, pretrazivaci moraju da sami otkrivaju stranice prateci linkove. Ovo moze rezultirati nepotpunim indeksiranjem.",
            "Without a sitemap, search engines must discover pages by following links. This may result in incomplete indexing.",
            "Kreirajte sitemap.xml i prijavite ga u Google Search Console.",
            "Create sitemap.xml and submit it in Google Search Console."))
    return results


def _check_robots_seo(base_url, session):
    results = []
    try:
        resp = session.get(base_url.rstrip("/") + "/robots.txt", timeout=TIMEOUT)
        if resp.status_code == 200 and len(resp.text) > 5:
            if "disallow: /" in resp.text.lower() and "disallow: / " not in resp.text.lower():
                lines = resp.text.lower().split("\n")
                for line in lines:
                    line = line.strip()
                    if line == "disallow: /":
                        results.append(_fail("seo_robots_block", "HIGH",
                            "robots.txt blokira sve pretrazivace!",
                            "robots.txt blocks all search engines!",
                            "Disallow: / u robots.txt blokira indeksiranje celokupnog sajta. Nijedna stranica nece biti u Google rezultatima.",
                            "Disallow: / in robots.txt blocks indexing of the entire site. No pages will appear in Google results.",
                            "Promenite na: Disallow: (prazno) ili uklonite tu liniju.",
                            "Change to: Disallow: (empty) or remove that line."))
                        return results
            results.append(_pass("seo_robots_ok",
                "robots.txt prisutan i pravilno konfigurisan",
                "robots.txt present and properly configured",
                "Pretrazivaci mogu indeksirati sajt.",
                "Search engines can index the site."))
        else:
            results.append(_fail("seo_robots_missing", "LOW",
                "robots.txt nedostaje",
                "robots.txt is missing",
                "Bez robots.txt, pretrazivaci indeksiraju sve stranice. To moze biti OK ali je bolje imati kontrolu.",
                "Without robots.txt, search engines index all pages. This may be OK but having control is better.",
                "Kreirajte robots.txt sa: User-agent: * / Allow: /",
                "Create robots.txt with: User-agent: * / Allow: /"))
    except Exception:
        pass
    return results


def _check_structured_data(body):
    results = []
    has_jsonld = '"@context"' in body and '"@type"' in body
    has_microdata = 'itemscope' in body.lower() and 'itemtype' in body.lower()

    if has_jsonld or has_microdata:
        stype = "JSON-LD" if has_jsonld else "Microdata"
        results.append(_pass("seo_structured_ok",
            f"Strukturirani podaci pronadjeni ({stype})",
            f"Structured data found ({stype})",
            "Sajt koristi strukturirane podatke za rich snippets u Google rezultatima.",
            "Site uses structured data for rich snippets in Google results."))
    else:
        results.append(_fail("seo_structured_missing", "LOW",
            "Strukturirani podaci (Schema.org) nedostaju",
            "Structured data (Schema.org) is missing",
            "Bez strukturiranih podataka, Google ne moze prikazati rich snippets (zvezdice, cene, FAQ) u rezultatima pretrage.",
            "Without structured data, Google cannot show rich snippets (stars, prices, FAQ) in search results.",
            "Dodajte JSON-LD strukturirane podatke. Generator: https://technicalseo.com/tools/schema-markup-generator/",
            "Add JSON-LD structured data. Generator: https://technicalseo.com/tools/schema-markup-generator/"))
    return results


def _pass(check_id, title_sr, title_en, desc_sr, desc_en):
    return {
        "id": check_id, "category": "SEO", "severity": "INFO", "passed": True,
        "title": title_sr, "title_en": title_en,
        "description": desc_sr, "description_en": desc_en,
        "recommendation": "", "recommendation_en": "",
    }


def _fail(check_id, severity, title_sr, title_en, desc_sr, desc_en, rec_sr, rec_en):
    return {
        "id": check_id, "category": "SEO", "severity": severity, "passed": False,
        "title": title_sr, "title_en": title_en,
        "description": desc_sr, "description_en": desc_en,
        "recommendation": rec_sr, "recommendation_en": rec_en,
    }
