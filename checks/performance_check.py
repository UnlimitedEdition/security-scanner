"""
Performance Check
Checks: TTFB, page size, compression, caching, external resources,
image optimization, lazy loading, minification, HTTP/2 support.
"""
import re
import ssl
import socket
from urllib.parse import urlparse
from typing import List, Dict, Any


def run(base_url: str, response_body: str, response_headers: dict,
        session, response_time_ms: float, page_size_bytes: int) -> List[Dict[str, Any]]:
    results = []

    results.extend(_check_ttfb(response_time_ms))
    results.extend(_check_page_size(page_size_bytes))
    results.extend(_check_compression(response_headers))
    results.extend(_check_cache_headers(response_headers))
    results.extend(_check_external_resources(response_body))
    results.extend(_check_image_optimization(response_body))
    results.extend(_check_lazy_loading(response_body))
    results.extend(_check_minification(response_body))
    results.extend(_check_http2(base_url))

    return results


# ── TTFB ────────────────────────────────────────────────────────────────────────
def _check_ttfb(response_time_ms):
    results = []
    if response_time_ms < 600:
        results.append(_pass("perf_ttfb",
            f"Vreme prvog bajta (TTFB) je dobro ({int(response_time_ms)} ms)",
            f"Time to First Byte (TTFB) is good ({int(response_time_ms)} ms)",
            f"TTFB od {int(response_time_ms)} ms je unutar preporucenog opsega (<600 ms).",
            f"TTFB of {int(response_time_ms)} ms is within the recommended range (<600 ms)."))
    elif response_time_ms <= 1500:
        results.append(_fail("perf_ttfb", "LOW",
            f"Vreme prvog bajta (TTFB) je povecano ({int(response_time_ms)} ms)",
            f"Time to First Byte (TTFB) is elevated ({int(response_time_ms)} ms)",
            f"TTFB od {int(response_time_ms)} ms je iznad idealne vrednosti od 600 ms. Ovo moze uticati na korisnicko iskustvo.",
            f"TTFB of {int(response_time_ms)} ms exceeds the ideal value of 600 ms. This may affect user experience.",
            "Optimizujte server-side procesiranje, koristite kesiranje i CDN.",
            "Optimize server-side processing, use caching and a CDN."))
    else:
        results.append(_fail("perf_ttfb", "MEDIUM",
            f"Vreme prvog bajta (TTFB) je previsoko ({int(response_time_ms)} ms)",
            f"Time to First Byte (TTFB) is too high ({int(response_time_ms)} ms)",
            f"TTFB od {int(response_time_ms)} ms je znacajno iznad preporuke od 600 ms. Korisnici ce primetiti sporije ucitavanje.",
            f"TTFB of {int(response_time_ms)} ms significantly exceeds the 600 ms recommendation. Users will notice slower loading.",
            "Hitno optimizujte server: proverite bazu podataka, kesirajte odgovore, koristite CDN i razmotrite bolji hosting.",
            "Urgently optimize the server: check database queries, cache responses, use a CDN, and consider better hosting."))
    return results


# ── Page size ───────────────────────────────────────────────────────────────────
def _check_page_size(page_size_bytes):
    results = []
    size_kb = page_size_bytes / 1024
    if size_kb < 200:
        results.append(_pass("perf_page_size",
            f"Velicina stranice je optimalna ({size_kb:.0f} KB)",
            f"Page size is optimal ({size_kb:.0f} KB)",
            f"Stranica je {size_kb:.0f} KB, sto je unutar preporucene granice od 200 KB.",
            f"Page is {size_kb:.0f} KB, within the recommended limit of 200 KB."))
    elif size_kb <= 500:
        results.append(_fail("perf_page_size", "LOW",
            f"Velicina stranice je povecana ({size_kb:.0f} KB)",
            f"Page size is elevated ({size_kb:.0f} KB)",
            f"Stranica je {size_kb:.0f} KB. Preporucena velicina je ispod 200 KB za brzo ucitavanje.",
            f"Page is {size_kb:.0f} KB. Recommended size is below 200 KB for fast loading.",
            "Smanjite velicinu stranice: kompresujte slike, minifikujte CSS/JS, uklonite nepotreban kod.",
            "Reduce page size: compress images, minify CSS/JS, remove unnecessary code."))
    else:
        results.append(_fail("perf_page_size", "MEDIUM",
            f"Velicina stranice je prevelika ({size_kb:.0f} KB)",
            f"Page size is too large ({size_kb:.0f} KB)",
            f"Stranica je {size_kb:.0f} KB, sto je znacajno iznad preporuke od 200 KB. Ovo posebno utice na mobilne korisnike.",
            f"Page is {size_kb:.0f} KB, significantly above the 200 KB recommendation. This especially affects mobile users.",
            "Hitno smanjite velicinu: optimizujte slike (WebP format), koristite lazy loading, minifikujte sve resurse.",
            "Urgently reduce size: optimize images (WebP format), use lazy loading, minify all resources."))
    return results


# ── Compression ─────────────────────────────────────────────────────────────────
def _check_compression(headers):
    results = []
    lower_headers = {k.lower(): v for k, v in headers.items()}
    encoding = lower_headers.get("content-encoding", "").lower()

    if any(enc in encoding for enc in ("gzip", "br", "deflate")):
        results.append(_pass("perf_compression",
            f"Kompresija aktivna ({encoding})",
            f"Compression active ({encoding})",
            f"Server koristi {encoding} kompresiju za smanjenje velicine prenosa.",
            f"Server uses {encoding} compression to reduce transfer size."))
    else:
        results.append(_fail("perf_compression", "MEDIUM",
            "HTTP kompresija nije aktivna",
            "HTTP compression is not active",
            "Server ne koristi gzip, Brotli niti deflate kompresiju. Ovo moze znacajno povecati vreme ucitavanja stranice.",
            "Server does not use gzip, Brotli, or deflate compression. This can significantly increase page load time.",
            "Omogucite gzip ili Brotli kompresiju na web serveru (Apache: mod_deflate, Nginx: gzip on).",
            "Enable gzip or Brotli compression on the web server (Apache: mod_deflate, Nginx: gzip on)."))
    return results


# ── Cache headers ───────────────────────────────────────────────────────────────
def _check_cache_headers(headers):
    results = []
    lower_headers = {k.lower(): v for k, v in headers.items()}

    has_cache_control = "cache-control" in lower_headers
    has_etag = "etag" in lower_headers
    has_expires = "expires" in lower_headers

    if has_cache_control or has_etag or has_expires:
        present = []
        if has_cache_control:
            present.append("Cache-Control")
        if has_etag:
            present.append("ETag")
        if has_expires:
            present.append("Expires")
        results.append(_pass("perf_cache",
            f"Cache headeri prisutni ({', '.join(present)})",
            f"Cache headers present ({', '.join(present)})",
            "Server koristi kesirajuce headere za smanjenje ponovnih zahteva.",
            "Server uses caching headers to reduce repeated requests."))
    else:
        results.append(_fail("perf_cache", "LOW",
            "Cache headeri nedostaju",
            "Cache headers are missing",
            "Nijedan od Cache-Control, ETag ili Expires headera nije pronadjen. Bez kesiranja, browser svaki put ponovo preuzima sve resurse.",
            "None of Cache-Control, ETag, or Expires headers found. Without caching, the browser re-downloads all resources on every visit.",
            "Dodajte Cache-Control header: Cache-Control: public, max-age=86400 za staticke resurse.",
            "Add a Cache-Control header: Cache-Control: public, max-age=86400 for static resources."))
    return results


# ── External resources ──────────────────────────────────────────────────────────
def _check_external_resources(body):
    results = []
    ext_scripts = re.findall(r'<script\s+[^>]*src=["\']https?://', body, re.IGNORECASE)
    ext_links = re.findall(r'<link\s+[^>]*href=["\']https?://', body, re.IGNORECASE)
    total = len(ext_scripts) + len(ext_links)

    if total <= 5:
        results.append(_pass("perf_external",
            f"Broj eksternih resursa je optimalan ({total})",
            f"Number of external resources is optimal ({total})",
            f"Pronadjeno {total} eksternih resursa (skripte i stilovi). Ovo je unutar preporucene granice.",
            f"Found {total} external resources (scripts and styles). This is within the recommended limit."))
    elif total <= 15:
        results.append(_fail("perf_external", "LOW",
            f"Povecan broj eksternih resursa ({total})",
            f"Elevated number of external resources ({total})",
            f"Pronadjeno {total} eksternih resursa. Svaki zahteva poseban DNS lookup i konekciju, sto usporava ucitavanje.",
            f"Found {total} external resources. Each requires a separate DNS lookup and connection, slowing page load.",
            "Smanjite broj eksternih resursa: kombinujte skripte, koristite lokalne kopije ili CDN sa preconnect.",
            "Reduce external resources: combine scripts, use local copies, or CDN with preconnect."))
    else:
        results.append(_fail("perf_external", "MEDIUM",
            f"Previse eksternih resursa ({total})",
            f"Too many external resources ({total})",
            f"Pronadjeno {total} eksternih resursa. Ovo znacajno usporava ucitavanje stranice zbog velikog broja HTTP zahteva.",
            f"Found {total} external resources. This significantly slows page loading due to a large number of HTTP requests.",
            "Hitno smanjite broj eksternih resursa: koristite bundler, uklonite nepotrebne skripte, self-hostujte kriticne resurse.",
            "Urgently reduce external resources: use a bundler, remove unnecessary scripts, self-host critical resources."))
    return results


# ── Image optimization ──────────────────────────────────────────────────────────
def _check_image_optimization(body):
    results = []
    img_tags = re.findall(r'<img\s+[^>]*?>', body, re.IGNORECASE)
    if not img_tags:
        results.append(_pass("perf_img_opt",
            "Nema slika na stranici",
            "No images on the page",
            "Nije pronadjena nijedna <img> oznaka na stranici.",
            "No <img> tags found on the page."))
        return results

    missing_opt = 0
    for img in img_tags:
        has_srcset = 'srcset=' in img.lower()
        has_width = 'width=' in img.lower()
        has_height = 'height=' in img.lower()
        if not has_srcset and not (has_width and has_height):
            missing_opt += 1

    if missing_opt > 3:
        results.append(_fail("perf_img_opt", "LOW",
            f"{missing_opt} slika bez optimizacije (od {len(img_tags)})",
            f"{missing_opt} images without optimization (of {len(img_tags)})",
            f"{missing_opt} slika nema srcset atribut niti eksplicitne width/height dimenzije. Ovo izaziva layout shift i sprecava responsivno ucitavanje.",
            f"{missing_opt} images lack srcset attribute or explicit width/height dimensions. This causes layout shift and prevents responsive loading.",
            "Dodajte width i height atribute svim slikama i koristite srcset za responsivne slike.",
            "Add width and height attributes to all images and use srcset for responsive images."))
    else:
        results.append(_pass("perf_img_opt",
            f"Slike su uglavnom optimizovane ({len(img_tags)} slika)",
            f"Images are mostly optimized ({len(img_tags)} images)",
            "Vecina slika ima odgovarajuce atribute za optimizaciju.",
            "Most images have appropriate optimization attributes."))
    return results


# ── Lazy loading ────────────────────────────────────────────────────────────────
def _check_lazy_loading(body):
    results = []
    img_tags = re.findall(r'<img\s+[^>]*?>', body, re.IGNORECASE)
    if not img_tags:
        results.append(_pass("perf_lazy_load",
            "Nema slika za proveru lazy loadinga",
            "No images to check for lazy loading",
            "Nije pronadjena nijedna <img> oznaka na stranici.",
            "No <img> tags found on the page."))
        return results

    without_lazy = 0
    for img in img_tags:
        if 'loading="lazy"' not in img.lower() and "loading='lazy'" not in img.lower():
            without_lazy += 1

    if without_lazy > 3:
        results.append(_fail("perf_lazy_load", "LOW",
            f"{without_lazy} slika bez lazy loadinga (od {len(img_tags)})",
            f"{without_lazy} images without lazy loading (of {len(img_tags)})",
            f"{without_lazy} slika nema loading=\"lazy\" atribut. Sve slike se ucitavaju odmah, sto usporava pocetno prikazivanje stranice.",
            f"{without_lazy} images lack the loading=\"lazy\" attribute. All images load immediately, slowing initial page render.",
            "Dodajte loading=\"lazy\" atribut slikama koje nisu vidljive odmah (ispod fold-a).",
            "Add loading=\"lazy\" attribute to images not immediately visible (below the fold)."))
    else:
        results.append(_pass("perf_lazy_load",
            f"Lazy loading je uglavnom implementiran ({len(img_tags)} slika)",
            f"Lazy loading is mostly implemented ({len(img_tags)} images)",
            "Vecina slika koristi lazy loading za efikasnije ucitavanje.",
            "Most images use lazy loading for more efficient loading."))
    return results


# ── Minification ────────────────────────────────────────────────────────────────
def _check_minification(body):
    results = []
    inline_styles = re.findall(r'<style[^>]*>(.*?)</style>', body, re.IGNORECASE | re.DOTALL)
    inline_scripts = re.findall(r'<script(?:\s[^>]*)?>(?!.*?src=)(.*?)</script>', body, re.IGNORECASE | re.DOTALL)

    # Filter out empty blocks and very short ones
    blocks = [b.strip() for b in inline_styles + inline_scripts if b.strip() and len(b.strip()) > 50]
    if not blocks:
        results.append(_pass("perf_minification",
            "Nema znacajnih inline blokova za minifikaciju",
            "No significant inline blocks to minify",
            "Nisu pronadjeni veliki inline <style> ili <script> blokovi.",
            "No large inline <style> or <script> blocks found."))
        return results

    unminified_count = 0
    for block in blocks:
        lines = block.strip().split('\n')
        # Heuristic: if many short lines relative to total length, likely unminified
        if len(lines) > 5:
            avg_line_len = len(block) / len(lines)
            if avg_line_len < 80:
                unminified_count += 1

    if unminified_count > 0:
        results.append(_fail("perf_minification", "LOW",
            f"{unminified_count} inline blokova nije minifikovano",
            f"{unminified_count} inline blocks are not minified",
            f"Pronadjeno {unminified_count} neminifikovanih inline <style> ili <script> blokova. Minifikacija moze smanjiti velicinu stranice za 20-40%.",
            f"Found {unminified_count} unminified inline <style> or <script> blocks. Minification can reduce page size by 20-40%.",
            "Minifikujte inline CSS i JavaScript. Koristite alate poput cssnano i terser.",
            "Minify inline CSS and JavaScript. Use tools like cssnano and terser."))
    else:
        results.append(_pass("perf_minification",
            "Inline blokovi su minifikovani",
            "Inline blocks are minified",
            "Svi inline <style> i <script> blokovi izgledaju minifikovano.",
            "All inline <style> and <script> blocks appear to be minified."))
    return results


# ── HTTP/2 ──────────────────────────────────────────────────────────────────────
def _check_http2(base_url):
    results = []
    parsed = urlparse(base_url)
    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    if parsed.scheme != "https":
        results.append(_fail("perf_http2", "LOW",
            "HTTP/2 provera preskocena (sajt ne koristi HTTPS)",
            "HTTP/2 check skipped (site does not use HTTPS)",
            "HTTP/2 zahteva HTTPS. Sajt koristi HTTP, pa HTTP/2 nije moguc.",
            "HTTP/2 requires HTTPS. Site uses HTTP, so HTTP/2 is not possible.",
            "Omogucite HTTPS na sajtu da biste mogli da koristite HTTP/2.",
            "Enable HTTPS on the site to be able to use HTTP/2."))
        return results

    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((hostname, port), timeout=7) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                protocol = ssock.selected_alpn_protocol()
                if protocol == "h2":
                    results.append(_pass("perf_http2",
                        "HTTP/2 podrzan",
                        "HTTP/2 supported",
                        "Server podrzava HTTP/2 protokol, sto omogucava multipleksiranje zahteva i brze ucitavanje.",
                        "Server supports HTTP/2 protocol, enabling request multiplexing and faster loading."))
                else:
                    results.append(_fail("perf_http2", "LOW",
                        "HTTP/2 nije podrzan",
                        "HTTP/2 is not supported",
                        f"Server koristi {protocol or 'HTTP/1.1'}. HTTP/2 omogucava multipleksiranje zahteva, kompresiju headera i server push.",
                        f"Server uses {protocol or 'HTTP/1.1'}. HTTP/2 enables request multiplexing, header compression, and server push.",
                        "Omogucite HTTP/2 na web serveru (vecina modernih servera ga podrzava).",
                        "Enable HTTP/2 on the web server (most modern servers support it)."))
    except Exception:
        results.append(_fail("perf_http2", "LOW",
            "Nije moguce proveriti HTTP/2 podrsku",
            "Unable to check HTTP/2 support",
            "Doslo je do greske prilikom provere HTTP/2 podrske putem ALPN pregovaranja.",
            "An error occurred while checking HTTP/2 support via ALPN negotiation.",
            "Proverite da li server podrzava HTTP/2 i da li je HTTPS pravilno konfigurisan.",
            "Verify that the server supports HTTP/2 and that HTTPS is properly configured."))
    return results


# ── Helpers ─────────────────────────────────────────────────────────────────────
def _pass(check_id, title_sr, title_en, desc_sr, desc_en):
    return {
        "id": check_id, "category": "Performance", "severity": "INFO", "passed": True,
        "title": title_sr, "title_en": title_en,
        "description": desc_sr, "description_en": desc_en,
        "recommendation": "", "recommendation_en": "",
    }


def _fail(check_id, severity, title_sr, title_en, desc_sr, desc_en, rec_sr, rec_en):
    return {
        "id": check_id, "category": "Performance", "severity": severity, "passed": False,
        "title": title_sr, "title_en": title_en,
        "description": desc_sr, "description_en": desc_en,
        "recommendation": rec_sr, "recommendation_en": rec_en,
    }
