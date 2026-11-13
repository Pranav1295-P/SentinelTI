/* SentinelTI — home page: mosaic hero, product demo, agent carousel, capabilities,
   tools, recent analyses and FAQ. */
(function () {
  const S = window.Sentinel;
  const T = window.SentinelTiles;
  const D = window.SentinelData;
  const API = window.SentinelAPI;
  const reduce = S.reduce;
  const $ = (s, root) => (root || document).querySelector(s);
  const $$ = (s, root) => [...(root || document).querySelectorAll(s)];
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const hasGsap = !!(window.gsap && window.ScrollTrigger);
  const chevron = (dir) => `<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6"><path d="${dir < 0 ? 'm10 3-5 5 5 5' : 'm6 3 5 5-5 5'}"/></svg>`;

  // ---------- Hero mosaic ----------
  const ROWS = [
    [['hex', 190], ['imports', 170], ['graph', 430], ['yara', 340], ['gauge', 240], ['attck', 320], ['strings', 260]],
    [['entropy', 400], ['chain', 310], ['hash', 260], ['radar', 300], ['fact', 310], ['hex', 240], ['pdf', 210]],
    [['strings', 200], ['rep', 300], ['drop', 190], ['attck', 280], ['gauge', 210], ['chain', 280], ['entropy', 340]],
    [['pdf', 220], ['yara', 300], ['radar', 240], ['imports', 210], ['hash', 300], ['graph', 360]],
  ];
  const mosaic = $('#mosaic');
  const unit = Math.max(.56, Math.min(1.25, innerWidth / 1440));
  mosaic.innerHTML = ROWS.map((row, r) => `<div class="hero__row" style="--drift:${r % 2 ? 1 : -1};--dur:${46 + r * 9}s">
    ${row.map(([kind, w], i) => `<div class="hero__cell" style="width:${Math.round(w * unit)}px">${T.render(kind, { seed: 11 + r * 7 + i })}</div>`).join('')}</div>`).join('');

  const pause = $('#hero-pause');
  pause.addEventListener('click', () => {
    const paused = document.documentElement.classList.toggle('motion-paused');
    pause.setAttribute('aria-pressed', paused);
    pause.setAttribute('aria-label', paused ? 'Play background motion' : 'Pause background motion');
    pause.innerHTML = paused ? '<svg viewBox="0 0 16 16" fill="currentColor"><path d="M4 2l10 6-10 6z"/></svg>' : '<svg viewBox="0 0 16 16" fill="currentColor"><path d="M4 2h3v12H4zM9 2h3v12H9z"/></svg>';
  });

  if (hasGsap && !reduce) {
    const word = $('#hero-word');
    word.innerHTML = [...word.textContent].map((c) => `<span class="ch">${c}</span>`).join('');
    word.setAttribute('aria-label', 'SentinelTI');
    gsap.from('.hero__cell', { opacity: 0, scale: .9, filter: 'blur(14px)', duration: 1.5, ease: 'expo.out', stagger: { each: .03, from: 'random' }, clearProps: 'filter,transform' });
    gsap.from('#hero-word .ch', { yPercent: 40, opacity: 0, filter: 'blur(18px)', duration: 1.5, ease: 'expo.out', stagger: .045, delay: .15, clearProps: 'filter' });
    gsap.from('.hero__foot > *', { y: 26, opacity: 0, filter: 'blur(10px)', duration: 1.2, ease: 'expo.out', stagger: .08, delay: .55, clearProps: 'filter' });
    gsap.to('.hero__mosaic', { scale: .9, opacity: .16, ease: 'none', scrollTrigger: { trigger: '.hero', start: 'top top', end: 'bottom top', scrub: true } });
    gsap.to('#hero-word', { yPercent: -28, ease: 'none', scrollTrigger: { trigger: '.hero', start: 'top top', end: 'bottom top', scrub: true } });
  }

  // ---------- Product demo: an example run playing inside a frame ----------
  const DEMO = [
    ['01', 'Triage Agent', 'Validated', ['Magic bytes → Windows PE (disguised as .pdf)', 'SHA-256 → e3b0c442…1a7c2d9e', 'Size 412 KB · entropy 7.82']],
    ['02', 'Evidence Agent', 'Evidence', ['PE I386 · 3 sections · 8 imports', 'YARA → Packer_UPX, Injection_API_Chain', '99 strings · 3 network indicators']],
    ['03', 'Behaviour Hypothesis Agent', '8 proven', ['Process Injection, Registry Run-key Persistence', 'Prompt injection text found and recorded']],
    ['04', 'Threat Context Agent', 'Mapped', ['ATT&CK → T1055, T1547.001, T1071.001, T1027.002', '3 internal notes matched']],
    ['05', 'Explainability & PDF Agent', 'Report', ['Verified 33 of 33 facts against the file', 'Evidence graph · PDF report ready']],
  ];
  const demo = $('#demo');
  demo.innerHTML = `<div class="frame__in" aria-hidden="true">
    <div class="frame__col frame__col--l">
      <div class="frame__title">Analyse</div>
      <div class="frame__label">Sessions</div>
      ${D.samples.slice(0, 5).map((s, i) => `<div class="frame__session${i === 0 ? ' is-on' : ''}"><b>${esc(s.file)}</b><span>${esc(s.verdict)} · ${esc(s.ago)}</span><i data-tone="${s.tone}"></i></div>`).join('')}
    </div>
    <div class="frame__col frame__col--c">
      <div class="frame__thread" id="demo-thread">
        <div class="frame__bubble">Analyse invoice_0923.pdf</div>
        ${DEMO.map(([n, name, label, lines]) => `<div class="frame__card"><div class="frame__card-head"><span>${n}</span><b>${esc(name)}</b><em class="chip"><span class="dot"></span>${esc(label)}</em></div>${lines.map((l) => `<p>${esc(l)}</p>`).join('')}</div>`).join('')}
        <div class="frame__verdict"><div><small>Verdict</small><strong>Critical</strong></div><div><small>Risk</small><strong>94</strong></div></div>
      </div>
      <div class="frame__composer"><span>Analyse here…</span><i></i></div>
    </div>
    <div class="frame__col frame__col--r">
      <div class="frame__title">Context &amp; To-Do</div>
      <div class="frame__label">Agent pipeline</div>
      ${D.agents.map((a) => `<div class="frame__todo"><i></i><span>${a.n} · ${esc(a.name)}</span></div>`).join('')}
    </div>
  </div>`;

  if (hasGsap && !reduce) {
    const thread = $('#demo-thread');
    const viewport = thread.parentElement;
    const cards = $$('.frame__card, .frame__verdict', thread);
    const todos = $$('.frame__todo', demo);
    const tl = gsap.timeline({ repeat: -1, repeatDelay: 2.4, paused: true });
    tl.set(cards, { opacity: 0, y: 18 }).set(thread, { y: 0 }).call(() => todos.forEach((t) => t.classList.remove('is-done')));
    cards.forEach((card, i) => {
      tl.to(card, { opacity: 1, y: 0, duration: .55, ease: 'expo.out' }, '+=.55');
      tl.to(thread, { y: () => Math.min(0, viewport.clientHeight - 74 - (card.offsetTop + card.offsetHeight)), duration: .6, ease: 'power2.inOut' }, '<');
      if (todos[i]) tl.call(() => todos[i].classList.add('is-done'), null, '<.3');
    });
    tl.to({}, { duration: .1 });
    ScrollTrigger.create({ trigger: demo, start: 'top 85%', end: 'bottom top', onToggle: (self) => (self.isActive ? tl.play() : tl.pause()) });
    gsap.from(demo, { scale: .92, ease: 'none', scrollTrigger: { trigger: demo, start: 'top 90%', end: 'top 30%', scrub: true } });
  } else {
    $$('.frame__todo', demo).forEach((t) => t.classList.add('is-done'));
  }

  // ---------- Agent carousel ----------
  const ART = ['fingerprint', 'entropy', 'chain', 'attck', 'fact'];
  const track = $('#agent-track');
  track.innerHTML = D.agents.map((a, i) => `<article class="acard" data-i="${i}">
    <div class="acard__art" aria-hidden="true">${T.render(ART[i], { seed: 40 + i })}</div>
    <div class="acard__body">
      <span class="acard__n">Agent ${a.n}</span>
      <h3>${esc(a.name.replace(' Hypothesis', '').replace(' & PDF', ''))}</h3>
      <p>${esc(a.aim)}</p>
      <div class="acard__tools">${a.tools.map((t) => `<span class="chip">${esc(t)}</span>`).join('')}</div>
      <div class="acard__cta"><a class="btn" data-emph="primary" href="analyse.html">Try in SentinelTI</a><a class="btn" href="about.html#agents">Learn more</a></div>
    </div>
  </article>`).join('');
  const acards = $$('.acard', track);
  function paintCarousel() {
    const mid = track.scrollLeft + track.clientWidth / 2;
    acards.forEach((c) => {
      const d = Math.abs(c.offsetLeft + c.offsetWidth / 2 - mid) / c.offsetWidth;
      c.style.setProperty('--dist', Math.min(1, d).toFixed(3));
    });
  }
  const scrollToCard = (i) => {
    const c = acards[Math.max(0, Math.min(acards.length - 1, i))];
    track.scrollTo({ left: c.offsetLeft + c.offsetWidth / 2 - track.clientWidth / 2, behavior: reduce ? 'auto' : 'smooth' });
  };
  const currentCard = () => acards.reduce((best, c, i) => {
    const d = Math.abs(c.offsetLeft + c.offsetWidth / 2 - (track.scrollLeft + track.clientWidth / 2));
    return d < best.d ? { d, i } : best;
  }, { d: Infinity, i: 0 }).i;
  track.addEventListener('scroll', () => requestAnimationFrame(paintCarousel), { passive: true });
  $('#agent-prev').addEventListener('click', () => scrollToCard(currentCard() - 1));
  $('#agent-next').addEventListener('click', () => scrollToCard(currentCard() + 1));
  track.addEventListener('keydown', (e) => {
    if (e.key === 'ArrowRight') { e.preventDefault(); scrollToCard(currentCard() + 1); }
    if (e.key === 'ArrowLeft') { e.preventDefault(); scrollToCard(currentCard() - 1); }
  });
  addEventListener('resize', paintCarousel);
  requestAnimationFrame(paintCarousel);

  // ---------- Capabilities ----------
  const CAPS = [
    {
      id: 'detect', word: 'Detect', side: 'l', ambient: '.2,.45,.75,.4', noteTitle: 'Know what it really is', note: 'A file named like a PDF can still be a Windows program. Agents read the magic bytes, hashes, headers, sections and strings, so nothing relies on what the file claims to be.',
      slides: [['fingerprint', 'Fingerprint', 'Real type, hashes and size, before anything else runs.'], ['entropy', 'Sections', 'High entropy and packer sections show what it is hiding.'], ['yara', 'YARA rules', 'Pattern matches you can extend with your own rules.']],
    },
    {
      id: 'correlate', word: 'Correlate', side: 'r', ambient: '.8,.5,.8,.5', noteTitle: 'Proof, not hunches', note: 'A capability only counts when its whole evidence chain is there. One suspicious API is a hint. The full injection chain is proof, and partial chains are kept apart as unproven hypotheses.',
      slides: [['chain', 'Evidence chains', 'APIs and strings correlated into capabilities.'], ['attck', 'MITRE ATT&CK', 'Proven findings mapped to real techniques.'], ['rep', 'Threat context', 'Reputation lookups and internal notes, by hash only.']],
    },
    {
      id: 'explain', word: 'Explain', side: 'l', ambient: '.25,.55,.7,.6', noteTitle: 'Every claim cites evidence', note: 'Agent 5 re-checks every fact against the file, then explains the verdict in plain English. Sentences with no verified evidence behind them are removed before you see them.',
      slides: [['live', 'Attack graph', 'Explore the evidence in an animated 3D graph.'], ['fact', 'Fact check', 'Every finding re-checked once against the file.'], ['pdf', 'PDF report', 'A report you can hand to your team.']],
    },
  ];
  $('#caps-body').innerHTML = CAPS.map((c) => `<article class="cap cap--${c.side}" id="cap-${c.id}" data-ambient="${c.ambient}">
    <h3 class="cap__word" data-cap-word>${c.word}</h3>
    <div class="cap__row">
      <div class="cap__stagewrap">
        <div class="stack" data-stack="${c.side}">
          ${c.slides.map(([kind, title]) => `<div class="stack__card"><div class="stack__bar"><span>${title}</span><em>Example</em></div><div class="stack__body" ${kind === 'live' ? 'data-live-graph' : ''}>${kind === 'live' ? '' : T.render(kind, { seed: 60 })}</div></div>`).join('')}
        </div>
        <div class="stack__foot">
          <p data-stack-cap>${c.slides[0][2]}</p>
          <div class="stack__nav"><button type="button" class="round-btn" data-stack-prev aria-label="Previous ${c.word} example">${chevron(-1)}</button><button type="button" class="round-btn" data-stack-next aria-label="Next ${c.word} example">${chevron(1)}</button></div>
        </div>
      </div>
      <aside class="cap__note" data-reveal><h4>${c.noteTitle}</h4><p>${c.note}</p></aside>
    </div>
  </article>`).join('');

  CAPS.forEach((c) => {
    const article = $('#cap-' + c.id);
    const stack = $('.stack', article);
    const cards = $$('.stack__card', stack);
    const caption = $('[data-stack-cap]', article);
    const dir = c.side === 'l' ? 1 : -1;
    let at = 0;
    const paint = () => cards.forEach((card, i) => {
      const k = (i - at + cards.length) % cards.length;
      card.style.setProperty('--k', k);
      card.style.setProperty('--dir', dir);
      card.setAttribute('aria-hidden', k !== 0);
      card.classList.toggle('is-front', k === 0);
    });
    const go = (d) => {
      at = (at + d + cards.length) % cards.length;
      paint();
      caption.textContent = c.slides[at][2];
      if (hasGsap && !reduce) gsap.fromTo(caption, { y: 10, opacity: 0, filter: 'blur(6px)' }, { y: 0, opacity: 1, filter: 'blur(0px)', duration: .6, ease: 'expo.out', clearProps: 'filter' });
    };
    $('[data-stack-prev]', article).addEventListener('click', () => go(-1));
    $('[data-stack-next]', article).addEventListener('click', () => go(1));
    paint();
  });

  // The Explain stack shows the real graph engine, started only when it comes into view.
  const liveHost = $('[data-live-graph]');
  let liveStarted = false;
  new IntersectionObserver((entries, observer) => {
    if (!entries[0].isIntersecting || liveStarted) return;
    liveStarted = true;
    observer.disconnect();
    window.SentinelGraph.create(liveHost, { graph: D.graph, risk: 94, labels: false, interactive: false, compact: true });
  }, { rootMargin: '200px' }).observe(liveHost);

  // Sticky bottom tabs
  const tabsBox = $('#caps-tabs');
  const pill = $('.caps__pill', tabsBox);
  tabsBox.insertAdjacentHTML('beforeend', CAPS.map((c) => `<a href="#cap-${c.id}" data-cap-tab="${c.id}">${c.word}</a>`).join(''));
  const tabs = $$('[data-cap-tab]', tabsBox);
  function setTab(id) {
    tabs.forEach((t) => {
      const on = t.dataset.capTab === id;
      if (on) t.setAttribute('aria-current', 'true'); else t.removeAttribute('aria-current');
      if (on) { pill.style.width = t.offsetWidth + 'px'; pill.style.transform = `translateX(${t.offsetLeft}px)`; }
    });
  }
  const refreshTab = () => { const on = tabs.find((t) => t.hasAttribute('aria-current')); setTab(on ? on.dataset.capTab : CAPS[0].id); };
  refreshTab();
  addEventListener('resize', refreshTab);
  if (document.fonts) document.fonts.ready.then(refreshTab);

  if (hasGsap) {
    CAPS.forEach((c) => {
      ScrollTrigger.create({ trigger: '#cap-' + c.id, start: 'top 55%', end: 'bottom 55%', onToggle: (self) => { if (self.isActive) setTab(c.id); } });
      if (reduce) return;
      gsap.fromTo(`#cap-${c.id} [data-cap-word]`, { y: 70, opacity: 0, filter: 'blur(26px)' }, { y: -10, opacity: 1, filter: 'blur(0px)', ease: 'none', scrollTrigger: { trigger: '#cap-' + c.id, start: 'top 92%', end: 'top 38%', scrub: .4 } });
      gsap.fromTo(`#cap-${c.id} .stack`, { y: 110, rotateX: 7 }, { y: 0, rotateX: 0, ease: 'none', scrollTrigger: { trigger: '#cap-' + c.id, start: 'top 80%', end: 'top 22%', scrub: .4 } });
    });
  }

  // ---------- Tools ----------
  const toolList = $('#tool-list');
  const preview = $('#tool-preview');
  toolList.innerHTML = D.tools.map((tool, i) => `<li class="tool" data-i="${i}" tabindex="0">
    <div class="tool__text"><h3>${esc(tool.name)}</h3><p>${esc(tool.use)}</p></div>
    <span class="chip tool__agent">Agent ${tool.agent}</span>
  </li>`).join('');
  preview.innerHTML = D.tools.map((tool, i) => `<div class="tools__slide" data-i="${i}">${T.render(tool.art, { seed: 80 + i })}<div class="tools__by"><span class="tools__mark">${S.markSVG('tools__markicon')}</span><div><small>Used by</small><b>Agent ${tool.agent}</b></div></div></div>`).join('');
  const toolItems = $$('.tool', toolList);
  const slides = $$('.tools__slide', preview);
  let activeTool = -1;
  function setTool(i) {
    if (i === activeTool) return;
    activeTool = i;
    toolItems.forEach((el, k) => el.classList.toggle('is-on', k === i));
    slides.forEach((el, k) => el.classList.toggle('is-on', k === i));
  }
  setTool(0);
  toolItems.forEach((el, i) => {
    el.addEventListener('pointerenter', () => setTool(i));
    el.addEventListener('focus', () => setTool(i));
    if (hasGsap) ScrollTrigger.create({ trigger: el, start: 'top 58%', end: 'bottom 58%', onToggle: (self) => { if (self.isActive) setTool(i); } });
  });

  // ---------- Recent analyses wheel ----------
  const wheel = $('#wheel');
  const ago = (iso) => {
    const s = Math.max(1, (Date.now() - new Date(iso)) / 1000);
    if (s < 3600) return Math.max(1, Math.floor(s / 60)) + 'm ago';
    if (s < 86400) return Math.floor(s / 3600) + 'h ago';
    return Math.floor(s / 86400) + 'd ago';
  };
  function buildWheel(items) {
    wheel.style.setProperty('--n', items.length);
    wheel.innerHTML = `<div class="wheel__stick">
      <ol class="wheel__names" aria-hidden="true">${items.map((it, i) => `<li data-i="${i}">${esc(it.file)}</li>`).join('')}</ol>
      <div class="wheel__visual" id="wheel-visual"></div>
      <div class="wheel__info" id="wheel-info"></div>
    </div>`;
    const names = $$('.wheel__names li', wheel);
    const visual = $('#wheel-visual');
    const info = $('#wheel-info');
    let shown = -1;
    function show(i) {
      if (i === shown) return;
      shown = i;
      const it = items[i];
      visual.innerHTML = `<a class="wheel__card" href="${esc(it.href)}" aria-label="Open the report for ${esc(it.file)}">${T.render('gauge', { value: it.risk, label: it.verdict })}<div class="wheel__strip">${it.sig.map((v) => `<i style="opacity:${(.18 + v * .82).toFixed(2)}"></i>`).join('')}</div></a>`;
      info.innerHTML = `<h3>${esc(it.title)}</h3><div class="wheel__chips"><span class="chip" data-tone="${esc(it.tone)}"><span class="dot"></span>${esc(it.verdict)}</span><span class="chip">${esc(it.ago)}</span></div><p>${esc(it.text)}</p><a class="btn" data-emph="primary" href="${esc(it.href)}">Open report</a>`;
      if (hasGsap && !reduce) {
        gsap.fromTo(info.children, { y: 22, opacity: 0, filter: 'blur(10px)' }, { y: 0, opacity: 1, filter: 'blur(0px)', duration: .7, ease: 'expo.out', stagger: .05, clearProps: 'filter' });
        gsap.fromTo(visual.firstElementChild, { rotateY: -22, rotateX: 8, scale: .9, opacity: 0 }, { rotateY: -7, rotateX: 3, scale: 1, opacity: 1, duration: .9, ease: 'expo.out' });
      }
    }
    function paint(pos) {
      names.forEach((li, i) => {
        const d = i - pos, abs = Math.abs(d);
        li.style.transform = `translateY(${d * 118}%)`;
        li.style.opacity = Math.max(0, 1 - abs * .42).toFixed(2);
        li.style.filter = abs < .5 ? 'none' : `blur(${Math.min(6, (abs - .5) * 4).toFixed(1)}px)`;
      });
      show(Math.round(pos));
    }
    paint(0);
    if (hasGsap && items.length > 1) {
      if (wheel._trigger) wheel._trigger.kill();
      wheel._trigger = ScrollTrigger.create({ trigger: wheel, start: 'top top', end: 'bottom bottom', onUpdate: (self) => paint(self.progress * (items.length - 1)) });
      ScrollTrigger.refresh();
    }
  }
  const examples = D.samples.map((s) => ({
    file: s.file, title: s.family, verdict: s.verdict, tone: s.tone, risk: s.risk, ago: 'Example', sig: s.sig, href: 'report.html',
    text: 'Example data, for illustration. Open it to explore the attack graph.',
  }));
  buildWheel(examples);
  API.list(8).then(({ items }) => {
    const done = items.filter((a) => a.status === 'completed');
    if (!done.length) { $('#wheel-intro').textContent = 'Example results for now. Analyse your first file and your own appear here.'; return; }
    $('#wheel-intro').textContent = 'Your latest results. Open any of them to explore the evidence.';
    buildWheel(done.map((a) => ({
      file: a.filename, title: a.family || 'No family attributed', verdict: a.verdict, tone: a.tone, risk: a.risk, ago: ago(a.created_at),
      sig: a.signals.length ? a.signals : [0, 0, 0, 0, 0], href: 'report.html?id=' + a.id,
      text: `SHA-256 ${a.sha256.slice(0, 16)}… analysed with ${a.llm_mode === 'llm' ? 'LLM agents and tools' : 'rule-based tools'}.`,
    })));
  }).catch(() => {});

  // ---------- Trust ----------
  const TRUST = [
    ['Never executed', 'Files are only read. Native parsers run in a locked-down, throwaway process with no secrets.'],
    ['Code sets the score', 'The risk score is calculated from verified evidence. No LLM, and no text inside a file, can change it.'],
    ['Every claim cites proof', 'Each fact is re-checked against the file. Sentences without verified evidence are removed.'],
    ['Your file stays put', 'Samples stay in read-only quarantine. Only the SHA-256 goes to VirusTotal and OTX.'],
  ];
  $('#trust-grid').innerHTML = TRUST.map(([t, p], i) => `<article class="tcard" data-reveal="${(i * .06).toFixed(2)}"><span>0${i + 1}</span><h3>${esc(t)}</h3><p>${esc(p)}</p></article>`).join('');

  // ---------- FAQ ----------
  const FAQ = [
    ['Who is SentinelTI for?', 'Security analysts and students who want a fast, explainable first look at a suspicious file, with the evidence in front of them.'],
    ['Does it run the file?', 'No. Analysis is static: the file is read, never executed. That also means behaviour that only appears at runtime can be missed, so it complements a sandbox rather than replacing one.'],
    ['What can it analyse?', 'Windows PE, Linux ELF and macOS Mach-O files get full structural analysis. Other files still get hashes, strings, indicators and YARA matching. ZIP archives are unpacked automatically, including password-protected malware archives that use the password infected. If something cannot be opened, the verdict is Inconclusive, never Clean. The upload limit is 100 MB.'],
    ['Can the AI change the verdict?', 'No. The score is computed in code from verified facts. Text inside a sample that tries to manipulate the AI is treated as evidence, and it raises the risk.'],
    ['What data leaves the server?', 'The SHA-256 goes to VirusTotal and AlienVault OTX, if those keys are set. Extracted strings and findings go to the LLM provider you configure. The file itself is never uploaded.'],
    ['Where do family names come from?', 'Only from a matching YARA rule or a reputation label. If neither names a family, SentinelTI says none was attributed rather than guessing.'],
  ];
  $('#faq-list').innerHTML = FAQ.map(([q, a], i) => `<div class="faq__item" data-reveal="${(i * .03).toFixed(2)}">
    <button type="button" aria-expanded="false" aria-controls="faq-${i}" id="faq-q-${i}"><span>${esc(q)}</span><i aria-hidden="true"></i></button>
    <div class="faq__a" id="faq-${i}" role="region" aria-labelledby="faq-q-${i}"><div><p>${esc(a)}</p></div></div>
  </div>`).join('');
  $('#faq-list').addEventListener('click', (e) => {
    const b = e.target.closest('button');
    if (!b) return;
    const open = b.getAttribute('aria-expanded') === 'true';
    b.setAttribute('aria-expanded', !open);
    b.parentElement.classList.toggle('is-open', !open);
    if (hasGsap) setTimeout(() => ScrollTrigger.refresh(), 500);
  });

  // Elements built above need the same reveal treatment as the static markup.
  if (hasGsap && !reduce) {
    $$('#trust-grid [data-reveal], #faq-list [data-reveal], #caps-body [data-reveal]').forEach((el) => {
      gsap.set(el, { y: 30, opacity: 0, filter: 'blur(14px)' });
      ScrollTrigger.create({ trigger: el, start: 'top 92%', once: true, onEnter: () => gsap.to(el, { y: 0, opacity: 1, filter: 'blur(0px)', duration: 1.1, ease: 'expo.out', delay: +el.dataset.reveal || 0, clearProps: 'filter' }) });
    });
  }
  if (S.ambient && hasGsap) {
    $$('#caps-body [data-ambient]').forEach((section) => {
      const [x, y, power, heat] = section.dataset.ambient.split(',').map(Number);
      ScrollTrigger.create({ trigger: section, start: 'top 60%', end: 'bottom 40%', onToggle: (self) => { if (self.isActive) S.ambient.tone(x, y, power, heat); } });
    });
  }
  if (hasGsap) { requestAnimationFrame(() => ScrollTrigger.refresh()); addEventListener('load', () => ScrollTrigger.refresh()); }

  // Arriving with a #hash: dynamic content has now changed the layout, so go there again.
  if (location.hash && location.hash.length > 1) {
    const target = $(location.hash);
    if (target) requestAnimationFrame(() => { if (S.lenis) S.lenis.scrollTo(target, { immediate: true, offset: -48 }); else target.scrollIntoView(); });
  }
})();
