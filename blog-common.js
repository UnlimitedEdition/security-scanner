/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Toske-Programer (Web Security Scanner contributors)
 * =============================================
   BLOG COMMON JS — Web Security Scanner
   Version: 2026-04-12-v3 (cookie consent loader + user-rights link)
   Last change: 2026-04-10 14:40 UTC
   Injects header, footer, timeline + lang toggle
   All content is static/trusted (no user input)
   ============================================= */

(function() {
  'use strict';

  // Version marker logged to console so you can verify which build
  // of blog-common.js is actually running. If you see "v2" here, the
  // latest deploy is live. If you don't see this line at all, your
  // browser is serving a cached version — hard refresh with Ctrl+F5
  // or test in an incognito window.
  try { console.log("%c[blog-common.js] v2 @ 2026-04-10 — loaded OK", "color:#22c55e;font-weight:bold"); } catch(_){}

  // ============================================================
  // SELF-XSS WARNING (big STOP message in devtools console)
  // ============================================================
  // This is the same pattern Facebook, Google, PayPal, Discord,
  // YouTube, Netflix, Twitter and every other consumer-grade site
  // with AdSense or auth uses. It protects AGAINST social-engineering
  // self-XSS attacks, where a scammer tells a non-technical victim:
  //
  //   "Paste this code in your console to unlock X feature!"
  //
  // The victim pastes, the scammer's code hijacks their session or
  // steals data. Browser vendors (Chrome/Firefox/Safari) explicitly
  // refuse to let websites lock devtools — that's a user right —
  // so the only defense is social: a giant visible "STOP" that
  // non-technical users will read and halt at.
  //
  // We CAN'T actually block console input from running. Overriding
  // window.console or using debugger traps is trivially bypassable
  // (Sources → Snippets, extensions, iframes, new-tab same-domain),
  // hostile to legitimate tools (ad blockers, accessibility), and
  // will get the site flagged by Google as "deceptive behavior".
  // The warning below is the actual industry standard, not a hack.
  //
  // Runs inside try/catch so a missing console (weird browsers,
  // unit tests, screen readers) doesn't break the rest of the page.
  try {
    var _stop = "color:#ef4444;font-size:56px;font-weight:900;" +
                "text-shadow:2px 2px 0 rgba(0,0,0,0.5);" +
                "padding:8px 16px;border:4px solid #ef4444;" +
                "border-radius:8px;background:#1a1e30;";
    var _title = "color:#fbbf24;font-size:17px;font-weight:800;" +
                 "padding:4px 0;";
    var _body = "color:#e6e8f0;font-size:13px;line-height:1.55;";
    var _accent = "color:#8b5cf6;font-size:12px;font-family:monospace;" +
                  "background:#0a0c15;padding:2px 6px;border-radius:4px;";

    // The top banner
    console.log("%c⛔ STOP!", _stop);

    // Serbian warning
    console.log("%c🇷🇸 UPOZORENJE — Web Security Scanner", _title);
    console.log(
      "%cOvo je alatka za programere (DevTools). Ako vam je neko rekao " +
      "da kopirate\n" +
      "i paste-ujete nesto ovde kako biste \"aktivirali\" neku funkciju, " +
      "dobili\n" +
      "besplatne skenove, \"hakovali\" nesto ili slicno — " +
      "TO JE PREVARA.\n\n" +
      "Ovo je napad koji se zove \"self-XSS\". Paste-ovanjem tudjeg koda " +
      "ovde\n" +
      "mozete:\n" +
      "  • izgubiti kontrolu nad vasim nalogom i scan istorijom\n" +
      "  • dozvoliti napadacu da salje zahteve u vase ime (abuse reports, " +
      "scanove)\n" +
      "  • otkriti kolacice trecim licima\n" +
      "  • postati deo bot-net mreze koja napada druge sajtove\n\n" +
      "Zatvorite ovu konzolu. Ne paste-ujte NISTA sto vam je neko poslao.\n" +
      "Ako ste programer i trebate dijagnoziku, kontaktirajte nas preko " +
      "zvanicnih\n" +
      "kanala (ispod).",
      _body
    );

    console.log("");

    // English warning
    console.log("%c🇬🇧 WARNING — Web Security Scanner", _title);
    console.log(
      "%cThis is a browser feature intended for developers (DevTools). " +
      "If someone\n" +
      "told you to copy and paste something here to \"enable\" a feature, " +
      "get\n" +
      "free scans, \"hack\" something, or similar — " +
      "IT IS A SCAM.\n\n" +
      "This attack is called \"self-XSS\". By pasting someone else's code " +
      "here\n" +
      "you may:\n" +
      "  • lose control of your account and scan history\n" +
      "  • allow the attacker to send requests on your behalf (abuse " +
      "reports, scans)\n" +
      "  • leak your cookies to third parties\n" +
      "  • become part of a botnet attacking other sites\n\n" +
      "Close this console. Do NOT paste anything someone sent you.\n" +
      "If you are a developer and need to debug, contact us via the " +
      "official\n" +
      "channels below.",
      _body
    );

    console.log("");

    // Legitimate contact info
    console.log("%cLegitimni kanali / Legitimate channels:", _title);
    console.log(
      "%c  https://toske-programer.web.app",
      _accent
    );
    console.log(
      "%c  /abuse-report.html     — prijavi zloupotrebu / report abuse",
      _accent
    );
    console.log(
      "%c  /privacy.html          — politika privatnosti / privacy policy",
      _accent
    );
    console.log(
      "%c  /terms.html            — uslovi koriscenja / terms of service",
      _accent
    );

    console.log("");

    // Closing note
    console.log(
      "%cIf you're a security researcher and found something interesting, " +
      "please\ncontact us via the channels above before publishing. " +
      "We respond within 72h.",
      "color:#8b92b0;font-size:12px;font-style:italic;"
    );
  } catch (_ignore) {
    // console not available (ancient browser, specific test runners) —
    // silently ignore; the warning is a "nice to have", not critical.
  }

  // --- Detect active category from URL ---
  var path = location.pathname;
  var fname = path.split('/').pop() || 'index.html';
  function isActive(cat) {
    if (cat === 'home') return fname === 'index.html' || fname === '' || fname === '/';
    if (cat === 'security') return fname.includes('security') && !fname.includes('scanner');
    if (cat === 'seo') return fname.includes('seo');
    if (cat === 'performance') return fname.includes('perf');
    if (cat === 'gdpr') return fname.includes('gdpr');
    if (cat === 'pricing') return fname.includes('pricing');
    return false;
  }

  // --- Helper: create element with attributes ---
  function el(tag, attrs, children) {
    var e = document.createElement(tag);
    if (attrs) Object.keys(attrs).forEach(function(k) {
      if (k === 'className') e.className = attrs[k];
      else if (k === 'textContent') e.textContent = attrs[k];
      else e.setAttribute(k, attrs[k]);
    });
    if (children) children.forEach(function(c) {
      if (typeof c === 'string') e.appendChild(document.createTextNode(c));
      else if (c) e.appendChild(c);
    });
    return e;
  }

  function srSpan(srText, enText) {
    var f = document.createDocumentFragment();
    f.appendChild(el('span', { className: 'sr' }, [srText]));
    f.appendChild(el('span', { className: 'en' }, [enText]));
    return f;
  }

  function navLink(href, srText, enText, active) {
    var a = el('a', { href: href, className: active ? 'active' : '' });
    a.appendChild(srSpan(srText, enText));
    return a;
  }

  function footerLink(href, text) {
    return el('a', { href: href }, [text]);
  }

  function footerLinkBi(href, srText, enText) {
    var a = el('a', { href: href });
    a.appendChild(srSpan(srText, enText));
    return a;
  }

  // --- BUILD HEADER ---
  var headerInner = el('div', { className: 'header-inner' });

  // Brand
  var brand = el('a', { href: './index.html', className: 'header-brand' });
  var svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('fill', 'none');
  svg.setAttribute('stroke', '#6c63ff');
  svg.setAttribute('stroke-width', '2.5');
  svg.setAttribute('stroke-linecap', 'round');
  var svgPath = document.createElementNS('http://www.w3.org/2000/svg', 'path');
  svgPath.setAttribute('d', 'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z');
  svg.appendChild(svgPath);
  brand.appendChild(svg);
  brand.appendChild(el('span', {}, ['Web Security Scanner']));
  var verBadge = el('span', { className: 'header-version' });
  verBadge.textContent = 'v3';
  verBadge.title = '2026-04-12-v3';
  brand.appendChild(verBadge);
  headerInner.appendChild(brand);

  // Hamburger
  var hamburger = el('button', { className: 'hamburger', 'aria-label': 'Menu' }, ['\u2630']);
  headerInner.appendChild(hamburger);

  // Nav
  var nav = el('nav', { className: 'header-nav' });
  nav.appendChild(navLink('./index.html', 'Pocetna', 'Home', isActive('home')));
  nav.appendChild(navLink('./blog-security.html', 'Bezbednost', 'Security', isActive('security')));
  nav.appendChild(navLink('./blog-seo.html', 'SEO', 'SEO', isActive('seo')));
  nav.appendChild(navLink('./blog-performance.html', 'Performanse', 'Performance', isActive('performance')));
  nav.appendChild(navLink('./blog-gdpr.html', 'GDPR', 'GDPR', isActive('gdpr')));

  // Pro pricing CTA — for free visitors. For subscribed users this
  // button swaps to an 'Account' link (see logic below after the header
  // is inserted into the DOM). Has its own CSS class so the accent
  // color + border can mark it as a premium upsell rather than another
  // editorial link.
  var proCta = el('a', {
    href: './pricing.html',
    className: isActive('pricing') ? 'nav-pro-cta active' : 'nav-pro-cta',
    id: 'nav-pro-cta',
  });
  proCta.appendChild(srSpan('Pro', 'Pro'));
  nav.appendChild(proCta);

  // Lang toggle in nav
  var langToggle = el('div', { className: 'lang-toggle' });
  var btnSr = el('button', { className: 'lang-btn active', 'data-lang': 'sr' }, ['SR']);
  var btnEn = el('button', { className: 'lang-btn', 'data-lang': 'en' }, ['EN']);
  langToggle.appendChild(btnSr);
  langToggle.appendChild(btnEn);
  nav.appendChild(langToggle);
  headerInner.appendChild(nav);

  var headerEl = el('header', { className: 'site-header' });
  headerEl.appendChild(headerInner);
  document.body.insertBefore(headerEl, document.body.firstChild);

  // Hamburger toggle
  hamburger.addEventListener('click', function() {
    nav.classList.toggle('open');
  });

  // --- BUILD FOOTER ---
  var footerGrid = el('div', { className: 'footer-grid' });

  // Security column
  var colSec = el('div', { className: 'footer-col' });
  var h4Sec = el('h4');
  h4Sec.appendChild(srSpan('Bezbednost', 'Security'));
  colSec.appendChild(h4Sec);
  colSec.appendChild(footerLinkBi('./blog-security.html', 'Vodic za bezbednost', 'Security Guide'));
  colSec.appendChild(footerLink('./blog-security-ssl.html', 'SSL/TLS'));
  colSec.appendChild(footerLink('./blog-security-headers.html', 'HTTP Headers'));
  colSec.appendChild(footerLink('./blog-security-xss.html', 'XSS'));
  colSec.appendChild(footerLink('./blog-security-sql.html', 'SQL Injection'));
  colSec.appendChild(footerLink('./blog-security-csrf.html', 'CSRF'));
  colSec.appendChild(footerLink('./blog-security-dns.html', 'DNS'));
  colSec.appendChild(footerLink('./blog-security-ports.html', 'Port Scanning'));
  colSec.appendChild(footerLink('./blog-security-api.html', 'API Security'));
  footerGrid.appendChild(colSec);

  // SEO column
  var colSeo = el('div', { className: 'footer-col' });
  colSeo.appendChild(el('h4', {}, ['SEO']));
  colSeo.appendChild(footerLinkBi('./blog-seo.html', 'SEO vodic', 'SEO Guide'));
  colSeo.appendChild(footerLink('./blog-seo-meta.html', 'Meta Tagovi'));
  colSeo.appendChild(footerLink('./blog-seo-schema.html', 'Schema.org'));
  colSeo.appendChild(footerLink('./blog-seo-sitemap.html', 'Sitemap.xml'));
  colSeo.appendChild(footerLink('./blog-seo-local.html', 'Lokalni SEO'));
  colSeo.appendChild(footerLink('./blog-seo-opengraph.html', 'Open Graph'));
  colSeo.appendChild(footerLink('./blog-seo-headings.html', 'Headings H1-H6'));
  colSeo.appendChild(footerLink('./blog-seo-mobile.html', 'Mobile SEO'));
  footerGrid.appendChild(colSeo);

  // Performance column
  var colPerf = el('div', { className: 'footer-col' });
  var h4Perf = el('h4');
  h4Perf.appendChild(srSpan('Performanse', 'Performance'));
  colPerf.appendChild(h4Perf);
  colPerf.appendChild(footerLinkBi('./blog-performance.html', 'Vodic za performanse', 'Performance Guide'));
  colPerf.appendChild(footerLink('./blog-perf-cwv.html', 'Core Web Vitals'));
  colPerf.appendChild(footerLink('./blog-perf-images.html', 'Optimizacija slika'));
  colPerf.appendChild(footerLink('./blog-perf-cache.html', 'HTTP Caching'));
  colPerf.appendChild(footerLink('./blog-perf-compression.html', 'Gzip & Brotli'));
  colPerf.appendChild(footerLink('./blog-perf-cdn.html', 'CDN'));
  colPerf.appendChild(footerLink('./blog-perf-lazy.html', 'Lazy Loading'));
  footerGrid.appendChild(colPerf);

  // GDPR column
  // GDPR column contains ONLY blog articles about GDPR — no legal pages.
  // Legal pages (privacy, terms, rights, abuse) live in their own row below.
  var colGdpr = el('div', { className: 'footer-col' });
  colGdpr.appendChild(el('h4', {}, ['GDPR']));
  colGdpr.appendChild(footerLinkBi('./blog-gdpr.html', 'GDPR vodic', 'GDPR Guide'));
  colGdpr.appendChild(footerLink('./blog-gdpr-cookies.html', 'Cookie Consent'));
  colGdpr.appendChild(footerLink('./blog-gdpr-policy.html', 'Privacy Policy'));
  colGdpr.appendChild(footerLink('./blog-gdpr-trackers.html', 'Third-Party Trackeri'));
  colGdpr.appendChild(footerLinkBi('./blog-gdpr-rights.html', 'Prava korisnika', 'User Rights'));
  colGdpr.appendChild(footerLinkBi('./blog-gdpr-fines.html', 'GDPR Kazne', 'GDPR Fines'));
  footerGrid.appendChild(colGdpr);

  // =====================================================================
  // LEGAL ROW — cleanly separated from blog articles above.
  // These are actual policy pages (or panels) that define the terms of
  // using this scanner, as opposed to the GDPR blog column which is
  // educational content about GDPR in general.
  // =====================================================================
  var legalRow = el('div', { className: 'footer-legal' });

  // Politika privatnosti — dedicated page
  var legalPrivacy = el('a', { href: './privacy.html' });
  legalPrivacy.appendChild(srSpan('Politika privatnosti', 'Privacy Policy'));
  legalRow.appendChild(legalPrivacy);

  // Uslovi koriscenja — dedicated page
  var legalTerms = el('a', { href: './terms.html' });
  legalTerms.appendChild(srSpan('Uslovi koriscenja', 'Terms of Service'));
  legalRow.appendChild(legalTerms);

  // Politika refundacije — dedicated page (Pro plan refund terms)
  var legalRefund = el('a', { href: './refund-policy.html' });
  legalRefund.appendChild(srSpan('Politika refundacije', 'Refund Policy'));
  legalRow.appendChild(legalRefund);

  // Prava korisnika — the user-rights blog article is the canonical source
  var legalRights = el('a', { href: './user-rights.html' });
  legalRights.appendChild(srSpan('Prava korisnika', 'User Rights'));
  legalRow.appendChild(legalRights);

  // Prijavi zloupotrebu — dedicated page with form + FAQ + process details
  var abuseLink = el('a', { href: './abuse-report.html' });
  abuseLink.appendChild(srSpan('Prijavi zloupotrebu', 'Report abuse'));
  legalRow.appendChild(abuseLink);

  // Podesavanja kolacica — reopens cookie consent banner
  var cookieLink = el('a', { href: '#' });
  cookieLink.style.cursor = 'pointer';
  cookieLink.addEventListener('click', function(e) {
    e.preventDefault();
    if (typeof openCookieSettings === 'function') openCookieSettings();
  });
  cookieLink.appendChild(srSpan('Podesavanja kolacica', 'Cookie Settings'));
  legalRow.appendChild(cookieLink);

  // Data protection badge in footer
  var badgeRow = el('div');
  badgeRow.style.cssText = 'display:flex;justify-content:center;padding:0.8rem 0;';
  var badgeLink = el('div');
  badgeLink.style.cssText = 'display:flex;align-items:center;gap:0.6rem;padding:0.5rem 0.8rem;background:rgba(124,58,237,0.06);border:1px solid rgba(124,58,237,0.15);border-radius:10px;';
  var badgeImg = el('img', { src: './data-protection-badge.png', alt: 'Data Protection', width: '40', height: '40' });
  badgeLink.appendChild(badgeImg);
  var badgeText = el('span');
  badgeText.style.cssText = 'font-size:0.68rem;color:rgba(255,255,255,0.45);line-height:1.3;';
  var btSr = el('span', { className: 'sr' });
  btSr.textContent = 'PII hashovan \u00b7 ZZPL uskladjen \u00b7 Enkriptovani backup-ovi';
  var btEn = el('span', { className: 'en' });
  btEn.textContent = 'PII hashed \u00b7 ZZPL compliant \u00b7 Encrypted backups';
  badgeText.appendChild(btSr);
  badgeText.appendChild(btEn);
  badgeLink.appendChild(badgeText);
  badgeRow.appendChild(badgeLink);

  // Footer bottom — just copyright + CTA
  var footerBottom = el('div', { className: 'footer-bottom' });
  var fbP = el('p');
  fbP.appendChild(document.createTextNode('Web Security Scanner \u00A9 2026 \u2014 '));
  fbP.appendChild(el('a', { href: 'https://toske-programer.web.app' }, ['<Toske/>']));
  footerBottom.appendChild(fbP);
  var fbCta = el('a', { href: './index.html', className: 'footer-cta' });
  fbCta.appendChild(srSpan('Skeniraj svoj sajt \u2192', 'Scan your site \u2192'));
  footerBottom.appendChild(fbCta);

  var footerEl = el('footer', { className: 'site-footer' });
  footerEl.appendChild(footerGrid);
  footerEl.appendChild(badgeRow);
  footerEl.appendChild(legalRow);
  footerEl.appendChild(footerBottom);
  document.body.appendChild(footerEl);

  // --- GLOBAL COOKIE CONSENT ---
  // Loads cookie-consent.js dynamically if not already present.
  // This gives all blog pages the same full GDPR V2 panel as index.html.
  if (!window._cookieConsentLoaded && !document.querySelector('script[src*="cookie-consent.js"]')) {
    var ccScript = document.createElement('script');
    ccScript.src = './cookie-consent.js';
    document.head.appendChild(ccScript);
  }

  // --- LANGUAGE TOGGLE ---
  function _blogSetLang(lang) {
    // Toggle lang-en class without wiping other body classes
    document.body.classList.toggle('lang-en', lang === 'en');
    document.querySelectorAll('.lang-btn').forEach(function(b) {
      var bLang = b.getAttribute('data-lang') || b.textContent.toLowerCase();
      b.classList.toggle('active', bLang === lang);
    });
    try { localStorage.setItem('wss-lang', lang); } catch(e) {}
  }

  // Restore saved language
  // IMPORTANT: call BOTH window.setLang (if page has its own full translator
  // that handles [data-sr][data-en] elements like index.html does) AND
  // _blogSetLang (which toggles body.lang-en for CSS-based .sr/.en spans).
  // Calling only _blogSetLang leaves data-sr/data-en elements stuck in Serbian
  // after the user picks EN and refreshes the page.
  try {
    var saved = localStorage.getItem('wss-lang');
    if (saved === 'en') {
      if (window.setLang && window.setLang !== _blogSetLang) {
        window.setLang('en');
      }
      _blogSetLang('en');
    }
  } catch(e) {}

  // Bind all lang buttons via delegation
  // If page defines its own window.setLang (index.html), call that instead
  document.addEventListener('click', function(e) {
    var btn = e.target.closest('.lang-btn');
    if (btn) {
      var lang = btn.getAttribute('data-lang') || btn.textContent.toLowerCase();
      if (window.setLang && window.setLang !== _blogSetLang) {
        window.setLang(lang);  // index.html's full setLang (translates data-sr/data-en)
      }
      _blogSetLang(lang);  // Always toggle body class + buttons for .sr/.en elements
    }
  });

  // Expose as fallback for pages without their own setLang
  if (!window.setLang) {
    window.setLang = _blogSetLang;
  }

  // --- TIMELINE SIDEBAR ---
  function initTimeline() {
    var content = document.querySelector('.blog-content');
    if (!content) return;

    var srList = document.getElementById('timeline-sr');
    var enList = document.getElementById('timeline-en');
    if (!srList && !enList) return;

    var h2s = content.querySelectorAll('h2[id]');
    var items = [];

    h2s.forEach(function(h2) {
      var li = el('li');
      var a = el('a', { href: '#' + h2.id, textContent: h2.textContent.replace(/^\d+\.\s*/, '') });
      li.appendChild(a);

      var parent = h2.closest('.sr') || h2.closest('.en');
      if (parent && parent.classList.contains('sr') && srList) {
        srList.appendChild(li);
      } else if (parent && parent.classList.contains('en') && enList) {
        enList.appendChild(li);
      }
      items.push({ el: h2, li: li });
    });

    if (items.length === 0) return;

    // Intersection Observer for active state
    var observer = new IntersectionObserver(function(entries) {
      entries.forEach(function(entry) {
        if (entry.isIntersecting) {
          items.forEach(function(item) {
            item.li.classList.toggle('active', item.el === entry.target);
          });
        }
      });
    }, { rootMargin: '-80px 0px -70% 0px' });

    items.forEach(function(item) { observer.observe(item.el); });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initTimeline);
  } else {
    initTimeline();
  }

  // --- Pro button → Account button swap when logged in ---
  //
  // When the visitor has a license key in localStorage, the Pro upsell
  // in the header becomes an "Account" link pointing at account.html.
  // This runs after the header has been inserted into the DOM above,
  // so we just look up the element by id and rewrite its href + label.
  // We do NOT hit the backend here — the full /api/subscription/me
  // check happens on account.html itself. Here we just trust the
  // presence of a key as a fast client-side hint, which is fine for
  // a nav label: worst case, a user with an expired key clicks
  // "Account" and gets redirected to /pricing.
  try {
    var licenseKey = localStorage.getItem('wss-license-key') || '';
    if (licenseKey) {
      var proBtn = document.getElementById('nav-pro-cta');
      if (proBtn) {
        proBtn.setAttribute('href', './account.html');
        proBtn.textContent = '';
        var isAccountPage = (location.pathname.indexOf('account') !== -1);
        if (isAccountPage) {
          proBtn.className = 'nav-pro-cta active';
        }
        var srLabel = document.createElement('span');
        srLabel.className = 'sr';
        srLabel.textContent = 'Nalog';
        var enLabel = document.createElement('span');
        enLabel.className = 'en';
        enLabel.textContent = 'Account';
        proBtn.appendChild(srLabel);
        proBtn.appendChild(enLabel);
      }
    }
  } catch (e) { /* localStorage disabled, fall through to Pro button */ }

})();
