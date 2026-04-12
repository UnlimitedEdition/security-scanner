/* ═══════════════════════════════════════════════════════════════════
   COOKIE CONSENT — GDPR granular (v2)
   Shared across ALL pages (index.html + blog pages).
   Loaded via <script src="./cookie-consent.js" defer></script>
   ═══════════════════════════════════════════════════════════════════ */
(function() {
  'use strict';
  if (window._cookieConsentLoaded) return;
  window._cookieConsentLoaded = true;

  // ── Helpers ────────────────────────────────────────────────────────
  function el(tag, attrs) {
    var e = document.createElement(tag);
    if (attrs) Object.keys(attrs).forEach(function(k) {
      if (k === 'className') e.className = attrs[k];
      else if (k === 'style') e.style.cssText = attrs[k];
      else e.setAttribute(k, attrs[k]);
    });
    return e;
  }
  function srEn(srText, enText) {
    var f = document.createDocumentFragment();
    var s = el('span', { className: 'sr' }); s.textContent = srText;
    var e = el('span', { className: 'en' }); e.textContent = enText;
    f.appendChild(s); f.appendChild(e);
    return f;
  }

  // ── Storage ────────────────────────────────────────────────────────
  function getConsent() {
    try { var r = localStorage.getItem('cookie_consent_v2'); return r ? JSON.parse(r) : null; }
    catch(e) { return null; }
  }
  function saveConsent(obj) {
    obj.essential = true;
    obj.timestamp = new Date().toISOString();
    try { localStorage.setItem('cookie_consent_v2', JSON.stringify(obj)); } catch(e) {}
  }

  // ── CSS ────────────────────────────────────────────────────────────
  function injectCSS() {
    if (document.getElementById('ccCSS')) return;
    var s = el('style', { id: 'ccCSS' });
    s.textContent = [
      '.cc-banner{position:fixed;bottom:0;left:0;right:0;z-index:99999;background:#0f1126;border-top:1px solid rgba(124,58,237,0.3);box-shadow:0 -4px 30px rgba(0,0,0,0.6);display:none;animation:ccSlide .4s ease-out}',
      '.cc-banner.visible{display:block}',
      '@keyframes ccSlide{from{transform:translateY(100%);opacity:0}to{transform:translateY(0);opacity:1}}',
      '.cc-inner{max-width:880px;margin:0 auto;padding:1.2rem 1.5rem}',
      '.cc-hdr{display:flex;align-items:center;gap:.6rem;margin-bottom:.7rem}',
      '.cc-hdr h4{margin:0;font-size:.95rem;color:#e2e8f0;flex:1;font-family:Inter,system-ui,sans-serif}',
      '.cc-desc{font-size:.8rem;color:rgba(255,255,255,.6);line-height:1.5;margin-bottom:1rem}',
      '.cc-desc a{color:#a78bfa;text-decoration:underline}',
      '.cc-cats{display:flex;flex-direction:column;gap:.5rem;margin-bottom:1rem}',
      '.cc-cat{display:flex;align-items:flex-start;gap:.7rem;padding:.7rem .9rem;background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.06);border-radius:8px}',
      '.cc-cat-tgl{flex-shrink:0;margin-top:.15rem}',
      '.cc-cat-tgl input{width:18px;height:18px;accent-color:#7c3aed;cursor:pointer}',
      '.cc-cat-tgl input:disabled{opacity:.5;cursor:default}',
      '.cc-cat-inf{flex:1}',
      '.cc-cat-nm{font-size:.82rem;font-weight:600;color:#e2e8f0;display:flex;align-items:center;gap:.4rem;font-family:Inter,system-ui,sans-serif}',
      '.cc-badge{font-size:.62rem;padding:.1rem .4rem;background:rgba(34,197,94,.15);color:#22c55e;border-radius:4px;font-weight:700;text-transform:uppercase}',
      '.cc-cat-d{font-size:.74rem;color:rgba(255,255,255,.45);line-height:1.4;margin-top:.2rem}',
      '.cc-cat-l{font-size:.68rem;color:rgba(255,255,255,.3);margin-top:.3rem;font-style:italic}',
      '.cc-acts{display:flex;gap:.6rem;flex-wrap:wrap}',
      '.cc-btn{padding:.6rem 1.3rem;border-radius:8px;font-size:.82rem;font-weight:600;cursor:pointer;border:none;font-family:Inter,system-ui,sans-serif;transition:all .15s}',
      '.cc-btn-a{background:#22c55e;color:#0a0c15}.cc-btn-a:hover{background:#16a34a}',
      '.cc-btn-s{background:#7c3aed;color:#fff}.cc-btn-s:hover{background:#6d28d9}',
      '.cc-btn-r{background:transparent;color:rgba(255,255,255,.5);border:1px solid rgba(255,255,255,.12)}.cc-btn-r:hover{border-color:rgba(255,255,255,.25);color:rgba(255,255,255,.8)}',
      '@media(max-width:600px){.cc-inner{padding:1rem}.cc-acts{flex-direction:column}.cc-btn{text-align:center}}',
    ].join('\n');
    document.head.appendChild(s);
  }

  // ── Build category row ─────────────────────────────────────────────
  function buildCat(opts) {
    var cat = el('div', { className: 'cc-cat' });
    var tgl = el('div', { className: 'cc-cat-tgl' });
    var cb = el('input', { type: 'checkbox', id: opts.id });
    if (opts.checked) cb.checked = true;
    if (opts.disabled) { cb.disabled = true; cb.checked = true; }
    tgl.appendChild(cb);
    cat.appendChild(tgl);

    var inf = el('div', { className: 'cc-cat-inf' });
    var nm = el('div', { className: 'cc-cat-nm' });
    nm.appendChild(srEn(opts.nameSr, opts.nameEn));
    if (opts.badge) {
      var badge = el('span', { className: 'cc-badge' });
      badge.appendChild(srEn(opts.badgeSr, opts.badgeEn));
      nm.appendChild(badge);
    }
    inf.appendChild(nm);

    var desc = el('div', { className: 'cc-cat-d' });
    desc.appendChild(srEn(opts.descSr, opts.descEn));
    inf.appendChild(desc);

    var list = el('div', { className: 'cc-cat-l' });
    list.appendChild(srEn(opts.listSr, opts.listEn));
    inf.appendChild(list);

    cat.appendChild(inf);
    return cat;
  }

  // ── Build banner DOM ───────────────────────────────────────────────
  function injectBanner() {
    if (document.getElementById('cookieBanner')) return;
    injectCSS();

    var banner = el('div', { className: 'cc-banner', id: 'cookieBanner', role: 'dialog' });
    banner.setAttribute('aria-label', 'Cookie consent');
    var inner = el('div', { className: 'cc-inner' });

    // Header
    var hdr = el('div', { className: 'cc-hdr' });
    var icon = el('span'); icon.textContent = '\uD83C\uDF6A';
    icon.style.cssText = 'font-size:1.3rem';
    var h4 = el('h4');
    h4.appendChild(srEn('Podesavanja kolacica', 'Cookie Settings'));
    hdr.appendChild(icon);
    hdr.appendChild(h4);
    inner.appendChild(hdr);

    // Description with links
    var desc = el('div', { className: 'cc-desc' });
    var dSr = el('span', { className: 'sr' });
    dSr.appendChild(document.createTextNode('Koristimo kolacice za rad sajta i poboljsanje vaseg iskustva. Mozete izabrati koje kategorije zelite da dozvolite. Detaljne informacije u nasoj '));
    var pLinkSr = el('a', { href: './privacy.html' }); pLinkSr.textContent = 'Politici privatnosti';
    dSr.appendChild(pLinkSr);
    dSr.appendChild(document.createTextNode(' i '));
    var cLinkSr = el('a', { href: './blog-gdpr-cookies.html' }); cLinkSr.textContent = 'Vodicu za kolacice';
    dSr.appendChild(cLinkSr);
    dSr.appendChild(document.createTextNode('.'));

    var dEn = el('span', { className: 'en' });
    dEn.appendChild(document.createTextNode('We use cookies to operate the site and improve your experience. You can choose which categories to allow. Details in our '));
    var pLinkEn = el('a', { href: './privacy.html' }); pLinkEn.textContent = 'Privacy Policy';
    dEn.appendChild(pLinkEn);
    dEn.appendChild(document.createTextNode(' and '));
    var cLinkEn = el('a', { href: './blog-gdpr-cookies.html' }); cLinkEn.textContent = 'Cookie Guide';
    dEn.appendChild(cLinkEn);
    dEn.appendChild(document.createTextNode('.'));

    desc.appendChild(dSr);
    desc.appendChild(dEn);
    inner.appendChild(desc);

    // Categories
    var cats = el('div', { className: 'cc-cats' });
    cats.appendChild(buildCat({
      id: 'ccEssential', checked: true, disabled: true,
      nameSr: 'Neophodni', nameEn: 'Essential',
      badge: true, badgeSr: 'Uvek aktivni', badgeEn: 'Always active',
      descSr: 'Potrebni za osnovni rad sajta: jezik, tema, sesija skeniranja, cookie saglasnost. Ne mogu se iskljuciti.',
      descEn: 'Required for basic site operation: language, theme, scan session, cookie consent. Cannot be disabled.',
      listSr: 'Kolacici: cookie_consent_v2 (localStorage), wss-lang, scan session ID',
      listEn: 'Cookies: cookie_consent_v2 (localStorage), wss-lang, scan session ID',
    }));
    cats.appendChild(buildCat({
      id: 'ccAnalytics',
      nameSr: 'Analiticki', nameEn: 'Analytics',
      descSr: 'Pomazu nam da razumemo kako koristite sajt: koje stranice posecujete, koliko dugo ostajete. Anonimizovani podaci.',
      descEn: 'Help us understand how you use the site: which pages you visit, how long you stay. Anonymized data.',
      listSr: 'Kolacici: Google Analytics (_ga, _gid) \u2014 trajanje: do 2 godine',
      listEn: 'Cookies: Google Analytics (_ga, _gid) \u2014 duration: up to 2 years',
    }));
    cats.appendChild(buildCat({
      id: 'ccAds',
      nameSr: 'Reklamni', nameEn: 'Advertising',
      descSr: 'Omogucavaju prikazivanje relevantnih reklama putem Google AdSense. Ovo finansira besplatni servis. Bez ovih kolacica, reklame nece biti prikazane.',
      descEn: 'Enable relevant ad display via Google AdSense. This funds the free service. Without these cookies, no ads will be shown.',
      listSr: 'Kolacici: Google AdSense (_gcl_*, IDE, NID, DSID, FLC, AID, TAID) \u2014 trece lice: Google LLC \u2014 trajanje: do 2 godine',
      listEn: 'Cookies: Google AdSense (_gcl_*, IDE, NID, DSID, FLC, AID, TAID) \u2014 third party: Google LLC \u2014 duration: up to 2 years',
    }));
    inner.appendChild(cats);

    // Action buttons
    var acts = el('div', { className: 'cc-acts' });
    var btnAccept = el('button', { className: 'cc-btn cc-btn-a' });
    btnAccept.appendChild(srEn('Prihvati sve', 'Accept All'));
    btnAccept.addEventListener('click', function() {
      saveConsent({ essential: true, analytics: true, ads: true });
      closeBanner(); applyConsent();
    });

    var btnSave = el('button', { className: 'cc-btn cc-btn-s' });
    btnSave.appendChild(srEn('Sacuvaj izbor', 'Save Choices'));
    btnSave.addEventListener('click', function() {
      var a = document.getElementById('ccAnalytics');
      var d = document.getElementById('ccAds');
      saveConsent({ essential: true, analytics: a && a.checked, ads: d && d.checked });
      closeBanner(); applyConsent();
    });

    var btnReject = el('button', { className: 'cc-btn cc-btn-r' });
    btnReject.appendChild(srEn('Odbij sve osim neophodnih', 'Reject All (Essential Only)'));
    btnReject.addEventListener('click', function() {
      saveConsent({ essential: true, analytics: false, ads: false });
      closeBanner(); applyConsent();
    });

    acts.appendChild(btnAccept);
    acts.appendChild(btnSave);
    acts.appendChild(btnReject);
    inner.appendChild(acts);

    banner.appendChild(inner);
    document.body.appendChild(banner);
  }

  function closeBanner() {
    var b = document.getElementById('cookieBanner');
    if (b) b.classList.remove('visible');
  }

  function openBanner() {
    injectBanner();
    var consent = getConsent();
    if (consent) {
      var a = document.getElementById('ccAnalytics');
      var d = document.getElementById('ccAds');
      if (a) a.checked = !!consent.analytics;
      if (d) d.checked = !!consent.ads;
    }
    var b = document.getElementById('cookieBanner');
    if (b) b.classList.add('visible');
  }

  // ── AdSense loader ─────────────────────────────────────────────────
  function applyConsent() {
    var consent = getConsent();
    if (consent && consent.ads) loadAdSense();
  }

  function loadAdSense() {
    if (window._adsenseLoaded) return;
    window._adsenseLoaded = true;
    if (!document.querySelector('script[src*="adsbygoogle"]')) {
      var s = el('script', { src: 'https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=ca-pub-6525862847461769', async: 'true', crossorigin: 'anonymous' });
      document.head.appendChild(s);
      var fc = el('script', { src: 'https://fundingchoicesmessages.google.com/i/pub-6525862847461769?ers=1', async: 'true' });
      document.head.appendChild(fc);
    }
    setTimeout(function() {
      document.querySelectorAll('.adsbygoogle').forEach(function(slot) {
        try { (window.adsbygoogle = window.adsbygoogle || []).push({}); } catch(e) {}
      });
    }, 1500);
  }

  // ── Init ───────────────────────────────────────────────────────────
  function init() {
    // Migrate v1 format
    try {
      var v1 = localStorage.getItem('cookie_consent');
      if (v1 && !getConsent()) {
        saveConsent({ essential: true, analytics: v1 === 'all', ads: v1 === 'all' });
        localStorage.removeItem('cookie_consent');
      }
    } catch(e) {}

    var consent = getConsent();
    if (!consent) {
      injectBanner();
      document.getElementById('cookieBanner').classList.add('visible');
    } else {
      applyConsent();
    }

    // Handle ?cookieSettings=1 from footer link on other pages
    if (location.search.indexOf('cookieSettings=1') >= 0) {
      openBanner();
      try { history.replaceState(null, '', location.pathname); } catch(e) {}
    }
  }

  // ── Public API ─────────────────────────────────────────────────────
  window.openCookieSettings = openBanner;
  window.getCookieConsent = getConsent;

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
