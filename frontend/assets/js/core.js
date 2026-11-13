/* SentinelTI — shared chrome, smooth scroll, reveals and the ambient field. */
(function () {
  document.documentElement.classList.add('js');

  const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const body = document.body;
  const page = body.dataset.page || '';
  const isApp = body.dataset.shell === 'app';

  // ---------- Markup helpers ----------
  const MARK_PATH =
    'M122 165 228 222 332 165 332 228 395 228 330 333 395 438 332 438 332 500 228 440 122 500 122 438 58 438 125 333 58 228 122 228Z' +
    'M125 232 170 333 125 435 228 378 330 435 285 333 330 232 228 290Z';

  let markCount = 0;
  function markSVG(cls) {
    const id = 'markGrad' + (++markCount);
    return `<svg class="${cls || 'brand__mark'}" viewBox="52 160 349 346" aria-hidden="true">
      <defs><linearGradient id="${id}" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0" stop-color="#fff3e0"/><stop offset=".42" stop-color="#ffb066"/><stop offset="1" stop-color="#ff6a00"/></linearGradient></defs>
      <path fill="url(#${id})" fill-rule="evenodd" d="${MARK_PATH}"/></svg>`;
  }
  const lockup = `${markSVG()}<span class="brand__word">SentinelTI</span>`;

  // ---------- Site header ----------
  const onHome = page === 'home';
  const NAV = [
    ['#overview', 'Overview'], ['#agents', 'Agents'], ['#capabilities', 'Capabilities'],
    ['#tools', 'Tools'], ['#analyses', 'Analyses'], ['#trust', 'Trust'],
  ];
  const navHref = (hash) => (onHome ? hash : 'index.html' + hash);

  function buildSiteHeader() {
    const links = NAV.map(([hash, label]) => `<a class="nav-link" href="${navHref(hash)}" data-spy="${hash.slice(1)}">${label}</a>`).join('');
    const about = `<a class="nav-link" href="about.html"${page === 'about' ? ' aria-current="page"' : ''}>How it Works</a>`;
    const header = document.createElement('header');
    header.className = 'site-head';
    header.innerHTML = `
      <a class="brand" href="${onHome ? '#top' : 'index.html'}" aria-label="SentinelTI home">${lockup}</a>
      <nav class="site-nav" aria-label="Primary">${links}${about}</nav>
      <div class="head-right">
        <a class="nav-link" href="login.html" data-auth>Login</a>
        <a class="btn" data-emph="primary" data-size="sm" href="analyse.html">Analyse</a>
        <button type="button" class="head-menu" aria-label="Menu" aria-expanded="false" aria-controls="menu-sheet">
          <svg viewBox="0 0 16 16" fill="currentColor"><circle cx="8" cy="3" r="1.5"/><circle cx="8" cy="8" r="1.5"/><circle cx="8" cy="13" r="1.5"/></svg>
        </button>
      </div>`;
    body.prepend(header);

    const sheet = document.createElement('div');
    sheet.className = 'menu-sheet';
    sheet.id = 'menu-sheet';
    sheet.innerHTML = `${NAV.map(([hash, label]) => `<a href="${navHref(hash)}">${label}</a>`).join('')}
      <a href="about.html">How it Works</a><a href="analyse.html">Analyse</a><a href="login.html" data-auth>Login</a>`;
    body.appendChild(sheet);

    const menu = header.querySelector('.head-menu');
    const setMenu = (open) => { sheet.classList.toggle('is-open', open); menu.setAttribute('aria-expanded', open); };
    menu.addEventListener('click', () => setMenu(!sheet.classList.contains('is-open')));
    sheet.addEventListener('click', (e) => { if (e.target.closest('a')) setMenu(false); });

    // Signed in: Login becomes Log out.
    if (window.SentinelAPI) {
      window.SentinelAPI.me().then(() => {
        document.querySelectorAll('[data-auth]').forEach((a) => {
          a.textContent = 'Log out';
          a.addEventListener('click', (e) => {
            e.preventDefault();
            window.SentinelAPI.logout().finally(() => { location.href = 'index.html'; });
          });
        });
      }).catch(() => {});
    }

    const skip = document.createElement('a');
    skip.className = 'skip-link';
    skip.href = '#main';
    skip.textContent = 'Skip to main content';
    body.prepend(skip);
  }

  // ---------- App shell: the logo and nothing else ----------
  function buildAppBar() {
    const bar = document.createElement('header');
    bar.className = 'app-bar';
    const href = body.dataset.brandHref;
    bar.innerHTML = href
      ? `<a class="brand" href="${href}" aria-label="SentinelTI">${lockup}</a>`
      : `<span class="brand" role="img" aria-label="SentinelTI">${lockup}</span>`;
    body.prepend(bar);
  }

  function buildFooter() {
    const host = document.querySelector('[data-footer]');
    if (!host) return;
    host.className = 'site-foot';
    host.innerHTML = `
      <span>SentinelTI by Relativity. Static analysis can miss behaviour that only appears at runtime, so review the evidence before acting.</span>
      <nav aria-label="Footer">
        <a href="about.html">How it Works</a>
        <a href="report.html">Example Attack Graph</a>
        <span>© ${new Date().getFullYear()}</span>
      </nav>`;
  }

  // ---------- Toast ----------
  let toastEl, toastTimer;
  function toast(msg) {
    if (!toastEl) {
      toastEl = document.createElement('div');
      toastEl.className = 'toast';
      toastEl.setAttribute('role', 'status');
      body.appendChild(toastEl);
    }
    toastEl.textContent = msg;
    requestAnimationFrame(() => toastEl.classList.add('is-on'));
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toastEl.classList.remove('is-on'), 2600);
  }

  // ---------- Links ----------
  let lenis = null;
  document.addEventListener('click', (e) => {
    const toastLink = e.target.closest('[data-toast]');
    if (toastLink) { e.preventDefault(); toast(toastLink.dataset.toast); return; }

    const a = e.target.closest('a[href]');
    if (!a) return;
    const href = a.getAttribute('href');

    // The workspace is its own environment, so the site always opens it in a new tab.
    if (!isApp && href.startsWith('analyse.html')) {
      a.target = '_blank';
      a.rel = 'noopener';
      return;
    }
    if (href.startsWith('#') && href.length > 1) {
      const target = document.querySelector(href);
      if (!target) return;
      e.preventDefault();
      if (lenis) lenis.scrollTo(target, { offset: href === '#top' ? 0 : -48, duration: 1.4 });
      else target.scrollIntoView({ behavior: reduce ? 'auto' : 'smooth' });
    }
  });

  // ---------- Ambient field ----------
  let ambient = null;
  function initAmbient() {
    if (body.dataset.ambient === 'off') return;
    const canvas = document.createElement('canvas');
    canvas.className = 'ambient';
    canvas.setAttribute('aria-hidden', 'true');
    body.prepend(canvas);
    if (window.SentinelAmbient) ambient = window.SentinelAmbient.make(canvas);
  }

  // ---------- Smooth scroll ----------
  function initScroll() {
    if (!window.Lenis || reduce || body.hasAttribute('data-no-lenis')) return;
    lenis = new Lenis({ duration: 1.15, easing: (t) => Math.min(1, 1.001 - Math.pow(2, -10 * t)) });
    if (window.gsap && window.ScrollTrigger) {
      lenis.on('scroll', ScrollTrigger.update);
      gsap.ticker.add((t) => lenis.raf(t * 1000));
      gsap.ticker.lagSmoothing(0);
    } else {
      const raf = (t) => { lenis.raf(t); requestAnimationFrame(raf); };
      requestAnimationFrame(raf);
    }
  }

  // ---------- Reveals, scroll-spy and ambient tone ----------
  function initReveals() {
    if (!window.gsap || !window.ScrollTrigger) return;
    gsap.registerPlugin(ScrollTrigger);
    if (document.fonts) document.fonts.ready.then(() => ScrollTrigger.refresh());

    if (!reduce) {
      document.querySelectorAll('[data-lines]').forEach((el) => {
        const inner = el.querySelectorAll('.line-mask > span');
        gsap.set(inner, { yPercent: 110 });
        ScrollTrigger.create({
          trigger: el, start: 'top 88%', once: true,
          onEnter: () => gsap.to(inner, { yPercent: 0, duration: 1, ease: 'expo.out', stagger: .08 }),
        });
      });
      document.querySelectorAll('[data-reveal]').forEach((el) => {
        gsap.set(el, { y: 30, opacity: 0, filter: 'blur(14px)' });
        ScrollTrigger.create({
          trigger: el, start: 'top 92%', once: true,
          onEnter: () => gsap.to(el, { y: 0, opacity: 1, filter: 'blur(0px)', duration: 1.1, ease: 'expo.out', delay: +el.dataset.reveal || 0, clearProps: 'filter' }),
        });
      });
    }

    const spyLinks = document.querySelectorAll('[data-spy]');
    if (spyLinks.length) {
      NAV.forEach(([hash]) => {
        const section = document.querySelector(hash);
        if (!section) return;
        ScrollTrigger.create({
          trigger: section, start: 'top 50%', end: 'bottom 50%',
          onToggle: (self) => {
            if (!self.isActive) return;
            spyLinks.forEach((a) => {
              if (a.dataset.spy === hash.slice(1)) a.setAttribute('aria-current', 'true');
              else a.removeAttribute('aria-current');
            });
          },
        });
      });
    }

    if (ambient) {
      document.querySelectorAll('[data-ambient]').forEach((section) => {
        const [x, y, power, heat] = section.dataset.ambient.split(',').map(Number);
        ScrollTrigger.create({
          trigger: section, start: 'top 60%', end: 'bottom 40%',
          onToggle: (self) => { if (self.isActive) ambient.tone(x, y, power, heat); },
        });
      });
    }
  }

  // ---------- Boot ----------
  if (isApp) buildAppBar(); else buildSiteHeader();
  buildFooter();
  initAmbient();
  initScroll();
  initReveals();
  if (ambient) ambient.show();

  window.Sentinel = { markSVG, toast, ready: Promise.resolve(), get lenis() { return lenis; }, get ambient() { return ambient; }, reduce };
})();
