/* SentinelTI — home: landing entrance, recent analyses, agent list. */
(function () {
  const { samples, agents } = window.SentinelData;
  const S = window.Sentinel;
  const API = window.SentinelAPI;
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  // ---------- Vortex ----------
  const vortex = window.SentinelVortex.make(document.querySelector('.landing__field'));

  // ---------- Library rows ----------
  const sigColor = (v) => {
    // indigo → violet → signal red as agent confidence rises
    if (v < .2) return `color-mix(in srgb, var(--signal-ok) ${40 + v * 200}%, var(--surface-raised))`;
    if (v < .6) return `color-mix(in srgb, var(--signal-amber) ${50 + v * 60}%, var(--brand-violet))`;
    return `color-mix(in srgb, var(--signal) ${v * 100}%, var(--brand-violet))`;
  };
  const body = document.getElementById('lib-body');
  const renderRows = (rows) => {
    body.innerHTML = rows.map((s) => `
    <a class="lib-row" role="row" href="${esc(s.href)}" data-tone="${esc(s.tone)}">
      <span role="cell" class="strip" aria-hidden="true">${s.sig.map((v) => `<i style="background:${sigColor(v)};flex:${.6 + v}"></i>`).join('')}</span>
      <span role="cell" class="lib-row__name"><span class="lib-row__file">${esc(s.file)}</span><span class="lib-row__family">${esc(s.family)}</span>
        <svg class="lib-row__arrow" width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M3 8h10M9 4l4 4-4 4"/></svg></span>
      <span role="cell"><span class="chip" data-tone="${esc(s.tone)}"><span class="dot"></span>${esc(s.verdict)}</span></span>
      <span role="cell" class="num">${esc(s.risk)}</span>
      <span role="cell" class="num" style="color:var(--on-surface-muted)">${esc(s.ago)}</span>
    </a>`).join('');
  };
  renderRows(samples.map((s) => ({ ...s, href: 'report.html' })));

  // Visitors see labelled examples; signed-in analysts see their own analyses.
  const heading = document.getElementById('lib-h');
  const source = document.createElement('span');
  source.className = 'chip';
  source.textContent = 'Example data';
  source.style.marginLeft = '12px';
  source.style.verticalAlign = 'middle';
  heading.appendChild(source);

  const ago = (iso) => {
    const s = Math.max(1, (Date.now() - new Date(iso)) / 1000);
    if (s < 3600) return Math.max(1, Math.floor(s / 60)) + 'm ago';
    if (s < 86400) return Math.floor(s / 3600) + 'h ago';
    return Math.floor(s / 86400) + 'd ago';
  };
  API.list(12).then(({ items }) => {
    source.remove();
    if (!items.length) {
      body.innerHTML = '<a class="lib-row" role="row" href="analyse.html"><span role="cell" class="lib-row__name" style="grid-column:1/-1"><span class="lib-row__file">No analyses yet</span><span class="lib-row__family">Drop your first sample in the workspace</span></span></a>';
      return;
    }
    renderRows(items.map((a) => {
      const done = a.status === 'completed';
      return {
        href: done ? 'report.html?id=' + a.id : 'analyse.html?id=' + a.id,
        tone: a.tone || '', file: a.filename,
        family: a.family || (done ? 'No family attributed' : a.status === 'failed' ? 'Analysis failed' : 'Analysing…'),
        verdict: a.verdict || (a.status === 'failed' ? 'Failed' : 'Running'),
        risk: a.risk ?? '—', ago: ago(a.created_at),
        sig: a.signals.length ? a.signals : [0, 0, 0, 0, 0],
      };
    }));
    if (window.ScrollTrigger) ScrollTrigger.refresh();
  }).catch(() => {});

  // ---------- Segmented filter ----------
  const seg = document.querySelector('.seg');
  const pill = seg.querySelector('.seg__pill');
  const movePill = (btn) => { pill.style.width = btn.offsetWidth + 'px'; pill.style.transform = `translateX(${btn.offsetLeft - 3}px)`; };
  seg.querySelectorAll('button').forEach((b) => b.addEventListener('click', () => {
    seg.querySelectorAll('button').forEach((x) => x.setAttribute('aria-pressed', x === b));
    movePill(b);
    const f = b.dataset.filter;
    const rows = body.querySelectorAll('.lib-row');
    rows.forEach((r) => {
      const t = r.dataset.tone;
      const show = f === 'all' || (f === 'crit' && t === 'crit') || (f === 'clean' && t === 'ok');
      r.classList.toggle('is-out', !show);
    });
    if (window.gsap) gsap.fromTo(body.querySelectorAll('.lib-row:not(.is-out)'), { opacity: 0, y: 10 }, { opacity: 1, y: 0, duration: .5, ease: 'expo.out', stagger: .04 });
  }));
  requestAnimationFrame(() => movePill(seg.querySelector('[aria-pressed="true"]')));
  addEventListener('resize', () => movePill(seg.querySelector('[aria-pressed="true"]')));

  // ---------- Agents ----------
  document.getElementById('agent-list').innerHTML = agents.map((a) => `
    <li class="agent">
      <span class="agent__n">${a.n}</span>
      <h3 class="agent__name">${a.name}</h3>
      <div class="agent__body">
        <p>${a.aim}</p>
        <div class="agent__tools">${a.tools.map((t) => `<span class="chip">${t}</span>`).join('')}</div>
        <span class="agent__out">Output → ${a.out}</span>
      </div>
      <span class="agent__bar" aria-hidden="true"></span>
    </li>`).join('');

  S.applySwaps();

  // ---------- Entrance + scroll motion ----------
  const lines = document.querySelectorAll('[data-land-line]');
  const cta = document.querySelector('[data-land-cta]');
  const credit = document.querySelector('[data-land-credit]');
  const legal = document.querySelector('[data-land-legal]');

  if (window.gsap && !S.reduce) {
    gsap.set(lines, { yPercent: 110 });
    gsap.set([cta, credit, legal], { opacity: 0, y: 16 });
  }

  S.ready.then(() => {
    vortex && vortex.show();
    if (!window.gsap || S.reduce) return;
    const tl = gsap.timeline({ defaults: { ease: 'expo.out' } });
    tl.to(lines, { yPercent: 0, duration: 1.1, stagger: .09 }, .15)
      .to(cta, { opacity: 1, y: 0, duration: 1 }, .55)
      .to(credit, { opacity: 1, y: 0, duration: 1 }, .7)
      .to(legal, { opacity: 1, y: 0, duration: 1 }, .75);

    // Landing drifts back as you leave it
    gsap.to('.landing__center', {
      yPercent: -18, opacity: 0, ease: 'none',
      scrollTrigger: { trigger: '.landing', start: 'top top', end: 'bottom top', scrub: true },
    });
    gsap.to('.landing__field', {
      scale: 1.12, ease: 'none',
      scrollTrigger: { trigger: '.landing', start: 'top top', end: 'bottom top', scrub: true },
    });

    // Library rows cascade; strips draw in
    ScrollTrigger.create({
      trigger: '.lib-table', start: 'top 85%', once: true,
      onEnter: () => {
        gsap.from('#lib-body .lib-row', { opacity: 0, y: 14, duration: .8, ease: 'expo.out', stagger: .05 });
        gsap.from('#lib-body .strip i', { scaleX: 0, duration: 1.1, ease: 'expo.out', stagger: .012 });
      },
    });

    // Agents: rule draws across as each row passes
    document.querySelectorAll('.agent').forEach((el) => {
      gsap.from(el.children, { opacity: 0, y: 20, duration: .9, ease: 'expo.out', stagger: .06,
        scrollTrigger: { trigger: el, start: 'top 85%', once: true } });
      gsap.to(el.querySelector('.agent__bar'), { scaleX: 1, ease: 'none',
        scrollTrigger: { trigger: el, start: 'top 75%', end: 'bottom 45%', scrub: true } });
    });
  });
})();
