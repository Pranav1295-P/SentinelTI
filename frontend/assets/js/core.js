/* SentinelTI — shared chrome, theme, loader, smooth scroll and reveals. */
(function () {
  const doc = document.documentElement;
  doc.classList.add('js');

  const THEME_KEY = 'sentinelti/theme';
  const store = {
    get(k) { try { return localStorage.getItem(k); } catch (e) { return null; } },
    set(k, v) { try { localStorage.setItem(k, v); } catch (e) {} },
  };
  const saved = store.get(THEME_KEY);
  doc.setAttribute('data-theme', saved === 'light' ? 'light' : 'dark');

  const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const page = document.body.dataset.page || '';

  // ---------- Markup helpers ----------
  const MARK_PATH =
    'M122 165 228 222 332 165 332 228 395 228 330 333 395 438 332 438 332 500 228 440 122 500 122 438 58 438 125 333 58 228 122 228Z' +
    'M125 232 170 333 125 435 228 378 330 435 285 333 330 232 228 290Z';

  function markSVG(cls) {
    return `<svg class="${cls || 'brand__mark'}" viewBox="52 160 349 346" aria-hidden="true">
      <defs><linearGradient id="markGrad" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0" stop-color="var(--on-surface)"/><stop offset=".55" stop-color="var(--on-surface)"/>
        <stop offset="1" stop-color="var(--on-surface)" stop-opacity=".45"/></linearGradient></defs>
      <path fill-rule="evenodd" d="${MARK_PATH}"/></svg>`;
  }

  function tswap(text) {
    return `<span class="tswap"><span class="tswap__a">${text}</span><span class="tswap__b" aria-hidden="true">${text}</span></span>`;
  }

  // Wrap any [data-swap] element's text in the rolling swap
  function applySwaps(root) {
    (root || document).querySelectorAll('[data-swap]:not([data-swapped])').forEach((el) => {
      el.setAttribute('data-swapped', '');
      const icon = el.querySelector('svg');
      const text = el.dataset.swap || el.textContent.trim();
      el.innerHTML = tswap(text);
      if (icon) el.prepend(icon);
    });
  }

  const glass = `<div class="glass-effect" aria-hidden="true"><span class="glass-effect__fill"></span><span class="glass-effect__burn"></span><span class="glass-effect__hl"></span><span class="glass-effect__edge-l"></span><span class="glass-effect__edge-d"></span><span class="glass-effect__glow"></span></div>`;

  function link(href, label, key) {
    const cur = page === key ? ' aria-current="page"' : '';
    return `<a class="nav-link" href="${href}"${cur}>${tswap(label)}</a>`;
  }

  function buildNav() {
    const header = document.createElement('header');
    header.className = 'glass-bar';
    header.setAttribute('data-arrive', '');
    header.innerHTML = `${glass}
      <div class="nav-left">
        <button type="button" class="theme-switch" role="switch" aria-checked="${doc.dataset.theme === 'light'}" aria-label="Light theme" title="Light theme">
          <span class="theme-switch__track"><span class="theme-switch__dot"></span></span>
        </button>
        <nav class="nav-links-desktop" aria-label="Primary" style="display:flex;gap:2px">
          ${link('index.html', 'Home', 'home')}
          ${link('analyse.html', 'Analyse', 'analyse')}
          ${link('report.html', 'Attack Graph', 'report')}
          ${link('about.html', 'How it Works', 'about')}
        </nav>
      </div>
      <a class="brand" href="index.html" aria-label="SentinelTI home">${markSVG()}<span class="brand__word">SentinelTI</span></a>
      <div class="nav-right">
        <span class="nav-links-desktop" style="display:flex">${link('login.html', 'Login', 'login')}</span>
        <a class="glass-cta nav-links-desktop" data-emph="primary" data-size="sm" href="analyse.html" style="display:inline-flex">
          <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M8 3v10M3 8h10"/></svg>${tswap('New Analysis')}</a>
        <button type="button" class="glass-cta nav-menu-btn" data-size="sm" aria-expanded="false" aria-controls="menu-sheet">${tswap('Menu')}</button>
      </div>`;
    document.body.prepend(header);

    const sheet = document.createElement('div');
    sheet.className = 'menu-sheet';
    sheet.id = 'menu-sheet';
    sheet.innerHTML = `<a href="index.html">Home</a><a href="analyse.html">Analyse</a><a href="report.html">Attack Graph</a><a href="about.html">How it Works</a><a href="login.html">Login</a>`;
    document.body.appendChild(sheet);

    const menuBtn = header.querySelector('.nav-menu-btn');
    menuBtn.addEventListener('click', () => {
      const open = sheet.classList.toggle('is-open');
      menuBtn.setAttribute('aria-expanded', open);
      menuBtn.querySelectorAll('.tswap__a,.tswap__b').forEach((s) => (s.textContent = open ? 'Close' : 'Menu'));
    });

    // Signed in: the Login links become Log out.
    if (window.SentinelAPI && document.body.dataset.page !== 'login') {
      window.SentinelAPI.me().then(() => {
        const out = (e) => {
          e.preventDefault();
          window.SentinelAPI.logout().finally(() => { location.href = 'index.html'; });
        };
        const desktop = header.querySelector('a[href="login.html"]');
        if (desktop) { desktop.innerHTML = tswap('Log out'); desktop.addEventListener('click', out); }
        const mobile = sheet.querySelector('a[href="login.html"]');
        if (mobile) { mobile.textContent = 'Log out'; mobile.addEventListener('click', out); }
      }).catch(() => {});
    }

    const sw = header.querySelector('.theme-switch');
    sw.addEventListener('click', () => {
      const light = doc.dataset.theme !== 'light';
      doc.setAttribute('data-theme', light ? 'light' : 'dark');
      sw.setAttribute('aria-checked', light);
      store.set(THEME_KEY, light ? 'light' : 'dark');
      window.dispatchEvent(new CustomEvent('themechange', { detail: { light } }));
    });

    const skip = document.createElement('a');
    skip.className = 'skip-link';
    skip.href = '#main';
    skip.textContent = 'Skip to Main Content';
    document.body.prepend(skip);
    return header;
  }

  function buildFooter() {
    const host = document.querySelector('[data-footer]');
    if (!host) return;
    const word = 'SentinelTI'.split('').map((c) => `<span class="ch">${c}</span>`).join('');
    host.className = 'site-foot';
    host.innerHTML = `
      <div class="site-foot__mark" aria-hidden="true">${word}</div>
      <div class="site-foot__row">
        <span>Autonomous Threat Intelligence · By Relativity</span>
        <nav aria-label="Footer">
          <a href="analyse.html">${tswap('Analyse')}</a>
          <a href="report.html">${tswap('Attack Graph')}</a>
          <a href="about.html">${tswap('How it Works')}</a>
          <a href="#" data-toast="Privacy policy coming soon">${tswap('Privacy')}</a>
          <a href="#" data-toast="Terms coming soon">${tswap('Terms')}</a>
        </nav>
        <span>All Rights Reserved © ${new Date().getFullYear()}</span>
      </div>`;
  }

  // ---------- Toast ----------
  let toastEl, toastT;
  function toast(msg) {
    if (!toastEl) {
      toastEl = document.createElement('div');
      toastEl.className = 'toast';
      toastEl.setAttribute('role', 'status');
      document.body.appendChild(toastEl);
    }
    toastEl.textContent = msg;
    requestAnimationFrame(() => toastEl.classList.add('is-on'));
    clearTimeout(toastT);
    toastT = setTimeout(() => toastEl.classList.remove('is-on'), 2400);
  }
  document.addEventListener('click', (e) => {
    const t = e.target.closest('[data-toast]');
    if (t) { e.preventDefault(); toast(t.dataset.toast); }
  });

  // ---------- Boot loader ----------
  // Wordmark rises 0.8s on the entrance ease, count follows; fill runs on a
  // randomly-shaped plan so no two visits look alike, then hands over.
  function runLoader() {
    return new Promise((resolve) => {
      const boot = document.querySelector('.boot');
      if (!boot || reduce || !boot.animate) { boot && boot.remove(); resolve(); return; }
      const word = boot.querySelector('.boot__word');
      const num = boot.querySelector('.boot__num');
      const fill = boot.querySelector('.boot__fill');
      const rise = (el, delay) => el.animate([{ transform: 'translateY(110%)' }, { transform: 'translateY(0)' }],
        { duration: 800, delay, easing: 'cubic-bezier(.16,1,.3,1)', fill: 'forwards' });
      rise(word, 240); rise(num, 420);

      const R = Math.random, pick = (a, b) => a + R() * (b - a);
      const shapes = [
        () => ({ w: [[0, pick(.34, .58)], [pick(240, 420), 1]], r: .07 }),
        () => { const a = pick(.12, .26); return { w: [[0, a], [pick(150, 260), a + pick(.24, .36)], [pick(380, 520), 1]], r: .07 }; },
        () => ({ w: [[0, pick(.05, .12)], [pick(200, 320), pick(.66, .82)], [pick(460, 600), 1]], r: .08 }),
        () => ({ w: [[0, 1]], r: R() < .5 ? pick(.032, .04) : pick(.06, .072) }),
      ];
      const P = shapes[Math.floor(R() * shapes.length)]();
      const plan = (t) => { let v = 0; for (const s of P.w) if (t >= s[0]) v = s[1]; return v; };

      let shown = 0, last = 0, start = 0, skip = false;
      const press = () => { skip = true; };
      addEventListener('pointerdown', press, { once: true });
      addEventListener('keydown', press, { once: true });

      const exit = () => {
        const out = { duration: 620, easing: 'cubic-bezier(.4,0,1,1)', fill: 'forwards' };
        word.animate([{ transform: 'translateY(0)' }, { transform: 'translateY(-110%)' }], out);
        num.animate([{ transform: 'translateY(0)' }, { transform: 'translateY(-110%)' }], { ...out, delay: 60 });
        const a = boot.animate([{ clipPath: 'inset(0 0 0 0)' }, { clipPath: 'inset(0 0 100% 0)' }],
          { duration: 900, delay: 280, easing: 'cubic-bezier(.19,1,.22,1)', fill: 'forwards' });
        setTimeout(resolve, 420);
        a.onfinish = () => boot.remove();
      };

      const loop = (ts) => {
        if (!start) start = ts;
        const dt = last ? Math.min(Math.max(ts - last, 1), 120) : 8.33;
        last = ts;
        const target = skip ? 1 : plan(ts - start);
        shown += (target - shown) * (1 - Math.pow(1 - P.r, dt / 8.33));
        if (target === 1 && shown > .995) shown = 1;
        num.textContent = String(Math.round(shown * 100));
        fill.style.transform = `scale3d(${shown},1,1)`;
        if (shown >= 1) { setTimeout(exit, 160); return; }
        requestAnimationFrame(loop);
      };
      setTimeout(() => requestAnimationFrame(loop), 640);
    });
  }

  // ---------- Smooth scroll + nav hide ----------
  let lenis = null;
  function initScroll(header) {
    if (window.Lenis && !reduce && !document.body.hasAttribute('data-no-lenis')) {
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
    let lastY = 0;
    const onScroll = () => {
      const y = window.scrollY;
      if (header && !document.body.hasAttribute('data-nav-static')) {
        if (y > 140 && y > lastY + 2) header.classList.add('is-hidden');
        else if (y < lastY - 2 || y <= 140) header.classList.remove('is-hidden');
      }
      lastY = y;
    };
    addEventListener('scroll', onScroll, { passive: true });
  }

  // ---------- Reveals ----------
  function initReveals() {
    if (!window.gsap) return;
    if (window.ScrollTrigger) {
      gsap.registerPlugin(ScrollTrigger);
      if (document.fonts) document.fonts.ready.then(() => ScrollTrigger.refresh());
    }

    document.querySelectorAll('[data-lines]').forEach((el) => {
      const inner = el.querySelectorAll('.line-mask > span');
      gsap.set(inner, { yPercent: 110 });
      ScrollTrigger.create({
        trigger: el, start: 'top 88%', once: true,
        onEnter: () => gsap.to(inner, { yPercent: 0, duration: .9, ease: 'expo.out', stagger: .08 }),
      });
    });

    document.querySelectorAll('[data-reveal]').forEach((el) => {
      gsap.set(el, { y: 24, opacity: 0 });
      ScrollTrigger.create({
        trigger: el, start: 'top 90%', once: true,
        onEnter: () => gsap.to(el, { y: 0, opacity: 1, duration: .9, ease: 'expo.out', delay: +el.dataset.reveal || 0 }),
      });
    });

    const chars = document.querySelectorAll('.site-foot__mark .ch');
    if (chars.length) {
      gsap.set(chars, { yPercent: 100 });
      ScrollTrigger.create({
        trigger: '.site-foot', start: 'top 85%', once: true,
        onEnter: () => gsap.to(chars, { yPercent: 0, duration: 1.1, ease: 'expo.out', stagger: .035 }),
      });
      document.querySelector('.site-foot__mark').style.overflow = 'hidden';
    }
  }

  // Arrival: nav drops in, [data-arrive] children fade/rise
  function arrive(header) {
    if (!window.gsap) return;
    if (reduce) { gsap.set(header, { clearProps: 'opacity' }); return; }
    gsap.fromTo(header, { y: -24, opacity: 0 }, { y: 0, opacity: 1, duration: 1, ease: 'expo.out', clearProps: 'transform,opacity' });
  }

  // ---------- Boot ----------
  const header = buildNav();
  buildFooter();
  applySwaps();

  const grain = document.createElement('div');
  grain.className = 'grain';
  grain.setAttribute('aria-hidden', 'true');
  document.body.appendChild(grain);

  if (window.gsap) gsap.set(header, { opacity: 0 });
  const ready = runLoader().then(() => {
    arrive(header);
    initScroll(header);
    initReveals();
    document.dispatchEvent(new CustomEvent('sentinel:ready'));
  });

  window.Sentinel = { tswap, applySwaps, markSVG, toast, ready, get lenis() { return lenis; }, reduce };
})();
