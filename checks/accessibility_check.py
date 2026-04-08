"""
Accessibility Check
Checks: images without alt, form labels, ARIA landmarks, heading hierarchy,
link text quality, language attribute, tabindex misuse.
"""
import re
from typing import List, Dict, Any


def _pass(check_id, title_sr, title_en, desc_sr, desc_en):
    return {
        "id": check_id, "category": "Accessibility", "severity": "INFO", "passed": True,
        "title": title_sr, "title_en": title_en,
        "description": desc_sr, "description_en": desc_en,
        "recommendation": "", "recommendation_en": "",
    }


def _fail(check_id, severity, title_sr, title_en, desc_sr, desc_en, rec_sr, rec_en):
    return {
        "id": check_id, "category": "Accessibility", "severity": severity, "passed": False,
        "title": title_sr, "title_en": title_en,
        "description": desc_sr, "description_en": desc_en,
        "recommendation": rec_sr, "recommendation_en": rec_en,
    }


def run(response_body: str) -> List[Dict[str, Any]]:
    results = []
    if not response_body:
        return results

    body = response_body

    # ── 1. Images Without Alt ─────────────────────────────────────────
    img_tags = re.findall(r'<img\s[^>]*?>', body, re.IGNORECASE)
    missing_alt = 0
    for img in img_tags:
        if 'alt=' not in img.lower():
            missing_alt += 1
        else:
            # Check for empty alt=""
            alt_match = re.search(r'alt=(["\'])\s*\1', img, re.IGNORECASE)
            if alt_match:
                missing_alt += 1

    if missing_alt > 0:
        results.append(_fail("a11y_img_no_alt", "MEDIUM",
            f"{missing_alt} slika bez alt atributa (od {len(img_tags)} ukupno)",
            f"{missing_alt} images without alt attribute (of {len(img_tags)} total)",
            f"Pronadjeno je {missing_alt} slika bez alt teksta ili sa praznim alt atributom. Korisnici citaca ekrana ne mogu da razumeju sadrzaj ovih slika.",
            f"Found {missing_alt} images without alt text or with empty alt attribute. Screen reader users cannot understand the content of these images.",
            "Dodajte opisni alt atribut svakoj slici: <img src=\"...\" alt=\"Opis sadrzaja slike\">. Dekorativne slike oznacite sa role=\"presentation\".",
            "Add descriptive alt attribute to each image: <img src=\"...\" alt=\"Image content description\">. Mark decorative images with role=\"presentation\"."))
    elif img_tags:
        results.append(_pass("a11y_img_alt_ok",
            f"Sve slike imaju alt atribut ({len(img_tags)} slika)",
            f"All images have alt attribute ({len(img_tags)} images)",
            "Sve slike na stranici imaju alt tekst, sto poboljsava pristupacnost.",
            "All images on the page have alt text, improving accessibility."))
    else:
        results.append(_pass("a11y_img_none",
            "Nema slika na stranici",
            "No images found on page",
            "Stranica ne sadrzi <img> tagove.",
            "Page contains no <img> tags."))

    # ── 2. Form Labels ────────────────────────────────────────────────
    # Find all <input> elements excluding hidden, submit, button types
    input_tags = re.findall(r'<input\s[^>]*?>', body, re.IGNORECASE)
    inputs_needing_label = []
    for inp in input_tags:
        type_match = re.search(r'type=["\']([^"\']+)["\']', inp, re.IGNORECASE)
        inp_type = type_match.group(1).lower() if type_match else "text"
        if inp_type in ("hidden", "submit", "button", "image", "reset"):
            continue
        inputs_needing_label.append(inp)

    unlabeled = 0
    for inp in inputs_needing_label:
        # Check for aria-label or aria-labelledby
        has_aria = bool(re.search(r'aria-label(?:ledby)?=', inp, re.IGNORECASE))
        if has_aria:
            continue
        # Check for id attribute and matching <label for="id">
        id_match = re.search(r'id=["\']([^"\']+)["\']', inp, re.IGNORECASE)
        if id_match:
            input_id = id_match.group(1)
            label_pattern = r'<label\s[^>]*for=["\']' + re.escape(input_id) + r'["\']'
            if re.search(label_pattern, body, re.IGNORECASE):
                continue
        # Check if input is wrapped inside a <label> tag (simplified check)
        # This is a basic check; wrapping detection is approximate with regex
        unlabeled += 1

    if unlabeled > 0:
        results.append(_fail("a11y_form_labels", "MEDIUM",
            f"{unlabeled} polja formulara bez labele (od {len(inputs_needing_label)})",
            f"{unlabeled} form inputs without labels (of {len(inputs_needing_label)})",
            f"Pronadjeno je {unlabeled} input polja bez povezane <label> oznake ili aria-label atributa. Korisnici sa citacima ekrana ne znaju sta treba da unesu.",
            f"Found {unlabeled} input fields without an associated <label> tag or aria-label attribute. Screen reader users don't know what to enter.",
            "Dodajte <label for=\"id\"> za svako input polje, ili koristite aria-label atribut.",
            "Add <label for=\"id\"> for each input field, or use the aria-label attribute."))
    elif inputs_needing_label:
        results.append(_pass("a11y_form_labels_ok",
            f"Sva polja formulara imaju labele ({len(inputs_needing_label)} polja)",
            f"All form inputs have labels ({len(inputs_needing_label)} inputs)",
            "Sva input polja imaju povezane labele ili aria-label atribute.",
            "All input fields have associated labels or aria-label attributes."))
    else:
        results.append(_pass("a11y_form_none",
            "Nema formulara na stranici",
            "No form inputs found on page",
            "Stranica ne sadrzi input polja koja zahtevaju labele.",
            "Page contains no input fields requiring labels."))

    # ── 3. ARIA Landmarks ─────────────────────────────────────────────
    aria_roles = re.findall(r'role=["\'](main|navigation|banner|contentinfo)["\']', body, re.IGNORECASE)
    semantic_tags = []
    for tag in ["<main", "<nav", "<header", "<footer"]:
        if re.search(re.escape(tag) + r'[\s>]', body, re.IGNORECASE):
            semantic_tags.append(tag.strip("<"))

    has_landmarks = len(aria_roles) > 0 or len(semantic_tags) > 0

    if has_landmarks:
        found_items = list(set([r.lower() for r in aria_roles] + semantic_tags))
        results.append(_pass("a11y_landmarks_ok",
            f"ARIA/HTML5 landmark elementi pronadjeni: {', '.join(found_items)}",
            f"ARIA/HTML5 landmark elements found: {', '.join(found_items)}",
            "Stranica koristi semanticke elemente ili ARIA role za navigaciju citacima ekrana.",
            "Page uses semantic elements or ARIA roles for screen reader navigation."))
    else:
        results.append(_fail("a11y_landmarks_missing", "LOW",
            "Nedostaju ARIA landmark elementi",
            "ARIA landmark elements are missing",
            "Stranica ne koristi ni ARIA role (main, navigation, banner, contentinfo) ni HTML5 semanticke tagove (<main>, <nav>, <header>, <footer>). Korisnici citaca ekrana ne mogu efikasno da navigiraju.",
            "Page uses neither ARIA roles (main, navigation, banner, contentinfo) nor HTML5 semantic tags (<main>, <nav>, <header>, <footer>). Screen reader users cannot navigate efficiently.",
            "Dodajte semanticke HTML5 tagove: <main> za glavni sadrzaj, <nav> za navigaciju, <header> i <footer>.",
            "Add semantic HTML5 tags: <main> for main content, <nav> for navigation, <header> and <footer>."))

    # ── 4. Heading Hierarchy ──────────────────────────────────────────
    headings = re.findall(r'<(h[1-6])[^>]*>', body, re.IGNORECASE)
    heading_levels = [int(h[1]) for h in headings]

    if heading_levels:
        skipped = False
        skipped_detail = []
        for i in range(1, len(heading_levels)):
            prev = heading_levels[i - 1]
            curr = heading_levels[i]
            # A skip is when we go deeper by more than 1 level (e.g., h1 -> h3)
            if curr > prev + 1:
                skipped = True
                skipped_detail.append(f"h{prev} -> h{curr}")

        if skipped:
            skip_str = ", ".join(skipped_detail[:3])
            results.append(_fail("a11y_heading_skip", "LOW",
                f"Preskoceni nivoi naslova: {skip_str}",
                f"Skipped heading levels: {skip_str}",
                f"Hijerarhija naslova preskace nivoe ({skip_str}). Ovo otezava navigaciju korisnicima citaca ekrana koji koriste naslove za kretanje po stranici.",
                f"Heading hierarchy skips levels ({skip_str}). This makes navigation difficult for screen reader users who use headings to navigate the page.",
                "Koristite naslove redom: h1, h2, h3 bez preskakanja. Nemojte birati nivo naslova po velicini fonta vec po strukturi.",
                "Use headings in order: h1, h2, h3 without skipping. Don't choose heading level by font size but by structure."))
        else:
            h_summary = ", ".join([f"h{l}" for l in heading_levels[:6]])
            results.append(_pass("a11y_heading_ok",
                "Hijerarhija naslova je ispravna",
                "Heading hierarchy is correct",
                f"Naslovi su u pravilnom redosledu bez preskakanja nivoa: {h_summary}{'...' if len(heading_levels) > 6 else ''}",
                f"Headings are in proper order without skipped levels: {h_summary}{'...' if len(heading_levels) > 6 else ''}"))
    else:
        results.append(_fail("a11y_heading_none", "LOW",
            "Nema naslova (h1-h6) na stranici",
            "No headings (h1-h6) found on page",
            "Stranica ne sadrzi nijedan naslov. Naslovi su kljucni za pristupacnost i strukturu sadrzaja.",
            "Page contains no headings. Headings are key for accessibility and content structure.",
            "Dodajte h1 naslov za glavni sadrzaj i h2/h3 za sekcije.",
            "Add an h1 heading for main content and h2/h3 for sections."))

    # ── 5. Link Text Quality ──────────────────────────────────────────
    # Find <a> tags and extract their text content
    link_matches = re.findall(r'<a\s[^>]*?>(.*?)</a>', body, re.IGNORECASE | re.DOTALL)
    bad_link_texts = ["click here", "here", "read more", "learn more", "more", "link"]
    bad_links_found = 0
    for link_text in link_matches:
        # Strip HTML tags inside the link
        clean_text = re.sub(r'<[^>]+>', '', link_text).strip().lower()
        if clean_text in bad_link_texts:
            bad_links_found += 1

    if bad_links_found > 3:
        results.append(_fail("a11y_link_text", "LOW",
            f"{bad_links_found} linkova sa neopisnim tekstom (\"click here\", \"read more\"...)",
            f"{bad_links_found} links with non-descriptive text (\"click here\", \"read more\"...)",
            f"Pronadjeno je {bad_links_found} linkova sa generickim tekstom. Korisnici citaca ekrana cesto listaju samo linkove — tekst poput \"kliknite ovde\" ne govori nista o destinaciji.",
            f"Found {bad_links_found} links with generic text. Screen reader users often browse links only — text like \"click here\" says nothing about the destination.",
            "Koristite opisni tekst linka koji govori kuda vodi: umesto \"kliknite ovde\" napisite \"preuzmite izvestaj za 2024.\"",
            "Use descriptive link text that indicates the destination: instead of \"click here\" write \"download the 2024 report.\""))
    else:
        results.append(_pass("a11y_link_text_ok",
            "Tekst linkova je dovoljno opisan",
            "Link text is sufficiently descriptive",
            f"Pronadjeno {bad_links_found} linkova sa generickim tekstom (prag: >3). Vecina linkova ima opisan tekst.",
            f"Found {bad_links_found} links with generic text (threshold: >3). Most links have descriptive text."))

    # ── 6. Language Attribute ─────────────────────────────────────────
    lang_match = re.search(r'<html[^>]*\slang=["\']([^"\']+)["\']', body, re.IGNORECASE)
    if lang_match:
        lang = lang_match.group(1)
        results.append(_pass("a11y_lang_ok",
            f"HTML lang atribut prisutan ({lang})",
            f"HTML lang attribute present ({lang})",
            f"Stranica ima definisan jezik: {lang}. Citaci ekrana koriste ovo za pravilan izgovor teksta.",
            f"Page has defined language: {lang}. Screen readers use this for correct text pronunciation."))
    else:
        results.append(_fail("a11y_lang_missing", "LOW",
            "HTML lang atribut nedostaje",
            "HTML lang attribute is missing",
            "Stranica nema lang atribut na <html> tagu. Citaci ekrana ne znaju kojim jezikom da citaju tekst, sto rezultira pogresnim izgovorom.",
            "Page has no lang attribute on <html> tag. Screen readers don't know which language to read text in, resulting in incorrect pronunciation.",
            "Dodajte: <html lang=\"sr\"> (ili odgovarajuci jezicki kod).",
            "Add: <html lang=\"en\"> (or appropriate language code)."))

    # ── 7. Tabindex Misuse ────────────────────────────────────────────
    tabindex_matches = re.findall(r'tabindex=["\'](\d+)["\']', body, re.IGNORECASE)
    positive_tabindex = [int(t) for t in tabindex_matches if int(t) > 0]

    if positive_tabindex:
        results.append(_fail("a11y_tabindex_positive", "LOW",
            f"{len(positive_tabindex)} elemenata sa pozitivnim tabindex (vrednosti: {', '.join(str(v) for v in sorted(set(positive_tabindex))[:5])})",
            f"{len(positive_tabindex)} elements with positive tabindex (values: {', '.join(str(v) for v in sorted(set(positive_tabindex))[:5])})",
            f"Pronadjeno je {len(positive_tabindex)} elemenata sa tabindex > 0. Pozitivne tabindex vrednosti remete prirodni redosled navigacije tastaturom i cine sajt tezim za koriscenje.",
            f"Found {len(positive_tabindex)} elements with tabindex > 0. Positive tabindex values disrupt the natural keyboard navigation order and make the site harder to use.",
            "Uklonite pozitivne tabindex vrednosti. Koristite tabindex=\"0\" za dodavanje u tok navigacije ili tabindex=\"-1\" za programski fokus.",
            "Remove positive tabindex values. Use tabindex=\"0\" to add to navigation flow or tabindex=\"-1\" for programmatic focus."))
    else:
        results.append(_pass("a11y_tabindex_ok",
            "Nema zloupotrebe tabindex atributa",
            "No tabindex misuse detected",
            "Nijedan element nema pozitivan tabindex, sto znaci da je redosled navigacije tastaturom prirodan.",
            "No elements have positive tabindex, meaning keyboard navigation order is natural."))

    return results
