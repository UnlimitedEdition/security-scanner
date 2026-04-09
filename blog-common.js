/* =============================================
   BLOG COMMON JS — Web Security Scanner
   Injects header, footer, timeline + lang toggle
   All content is static/trusted (no user input)
   ============================================= */

(function() {
  'use strict';

  // --- Detect active category from URL ---
  var path = location.pathname;
  var fname = path.split('/').pop() || 'index.html';
  function isActive(cat) {
    if (cat === 'home') return fname === 'index.html' || fname === '' || fname === '/';
    if (cat === 'security') return fname.includes('security');
    if (cat === 'seo') return fname.includes('seo');
    if (cat === 'performance') return fname.includes('perf');
    if (cat === 'gdpr') return fname.includes('gdpr');
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
  var colGdpr = el('div', { className: 'footer-col' });
  colGdpr.appendChild(el('h4', {}, ['GDPR']));
  colGdpr.appendChild(footerLinkBi('./blog-gdpr.html', 'GDPR vodic', 'GDPR Guide'));
  colGdpr.appendChild(footerLink('./blog-gdpr-cookies.html', 'Cookie Consent'));
  colGdpr.appendChild(footerLink('./blog-gdpr-policy.html', 'Privacy Policy'));
  colGdpr.appendChild(footerLink('./blog-gdpr-trackers.html', 'Third-Party Trackeri'));
  colGdpr.appendChild(footerLinkBi('./blog-gdpr-rights.html', 'Prava korisnika', 'User Rights'));
  colGdpr.appendChild(footerLinkBi('./blog-gdpr-fines.html', 'GDPR Kazne', 'GDPR Fines'));
  colGdpr.appendChild(footerLinkBi('./privacy.html', 'Politika privatnosti', 'Privacy Policy'));
  footerGrid.appendChild(colGdpr);

  // Footer bottom
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
  footerEl.appendChild(footerBottom);
  document.body.appendChild(footerEl);

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
  try {
    var saved = localStorage.getItem('wss-lang');
    if (saved === 'en') _blogSetLang('en');
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

})();
