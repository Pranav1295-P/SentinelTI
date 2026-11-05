/* SentinelTI — evidence graph: pan, zoom, drag, select, draw-in. */
(async function () {
  const S = window.Sentinel;
  const API = window.SentinelAPI;
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const analysisId = new URLSearchParams(location.search).get('id');
  let graph = window.SentinelData.graph;

  // ---------- A real report, when the URL names one ----------
  function fillHeader(a) {
    const r = a.result || {};
    const iocs = r.iocs || {};
    document.querySelector('.report-head h1 .line-mask > span').textContent = a.filename;
    document.title = a.filename + ' | SentinelTI';
    const t = r.triage || {};
    const chips = [
      `<span class="chip" data-tone="${esc(a.tone)}"><span class="dot"></span>${esc(a.verdict)}</span>`,
      a.family ? `<span class="chip">${esc(a.family)}</span>` : '',
      t.label ? `<span class="chip">${esc(t.label)}</span>` : '',
      `<span class="chip mono" title="${esc(a.sha256)}">${esc(a.sha256.slice(0, 12))}…</span>`,
    ];
    document.querySelector('.report-head__meta').innerHTML = chips.join('');
    const counts = document.querySelectorAll('.report-stats [data-count]');
    [a.risk, (r.techniques || []).length, (iocs.urls || []).length + (iocs.ips || []).length, 5].forEach((v, i) => { counts[i].dataset.count = v; });

    const table = document.getElementById('mitre-table');
    table.querySelectorAll('a.lib-row, .lib-row--empty').forEach((row) => row.remove());
    const nodeIds = new Set(graph.nodes.map((n) => n.id));
    const facts = Object.fromEntries((r.facts || []).map((f) => [f.id, f]));
    const rows = (r.techniques || []).map((x) => {
      const node = x.capability_ids.map((c) => 'cap-' + c).find((c) => nodeIds.has(c)) || 'sample';
      const proof = x.evidence_ids.map((e) => (facts[e] || {}).title).filter(Boolean).slice(0, 3).join(' · ');
      return `<a class="lib-row" role="row" href="#graph" data-node="${esc(node)}"><span role="cell" class="mono">${esc(x.id)}</span><span role="cell">${esc(x.name)}</span><span role="cell" class="lib-row__family">${esc(proof)}</span><span role="cell" class="num">${esc(x.confidence.toFixed(2))}</span></a>`;
    });
    table.insertAdjacentHTML('beforeend', rows.join('') || '<div class="lib-row lib-row--empty" role="row"><span role="cell" style="grid-column:1/-1;color:var(--on-surface-muted)">No techniques were proven for this sample.</span></div>');
  }
  if (analysisId) {
    try {
      const [detail, realGraph] = await Promise.all([API.get(analysisId), API.graph(analysisId)]);
      graph = realGraph;
      fillHeader(detail);
    } catch (err) {
      if (err.status === 401) { location.href = API.loginUrl(); return; }
      if (err.status === 409) { location.href = 'analyse.html?id=' + encodeURIComponent(analysisId); return; }
      S.toast(err.status === 404 ? 'That report was not found, so this is the example' : err.message);
    }
  }
  const NS = 'http://www.w3.org/2000/svg';
  const host = document.getElementById('graph');
  const svg = document.getElementById('graph-svg');
  const detail = document.getElementById('detail');
  const zVal = document.getElementById('z-val');

  const COLORS = { sample: 'var(--on-surface)', evidence: 'var(--brand-violet)', capability: 'var(--signal)', network: 'var(--signal-amber)', intel: '#a99cff' };
  const RADIUS = { sample: 26, evidence: 15, capability: 17, network: 16, intel: 15 };
  const el = (tag, attrs, parent) => { const e = document.createElementNS(NS, tag); for (const k in attrs) e.setAttribute(k, attrs[k]); if (parent) parent.appendChild(e); return e; };

  const defs = el('defs', {}, svg);
  const mk = el('marker', { id: 'arrow', viewBox: '0 0 10 10', refX: 9, refY: 5, markerWidth: 7, markerHeight: 7, orient: 'auto-start-reverse' }, defs);
  el('path', { d: 'M0 1 10 5 0 9Z', fill: 'color-mix(in srgb, var(--on-surface) 50%, transparent)' }, mk);

  const view = el('g', {}, svg);
  const gEdges = el('g', {}, view);
  const gNodes = el('g', {}, view);

  const nodes = graph.nodes.map((n) => ({ ...n }));
  const byId = Object.fromEntries(nodes.map((n) => [n.id, n]));
  const edges = graph.edges.map(([a, b]) => ({ a: byId[a], b: byId[b] }));

  // ---------- Build ----------
  edges.forEach((e) => { e.path = el('path', { class: 'g-edge', 'marker-end': 'url(#arrow)' }, gEdges); });
  nodes.forEach((n, i) => {
    const r = RADIUS[n.type];
    const g = el('g', { class: 'g-node', tabindex: 0, role: 'button', 'aria-label': `${n.label}, ${n.type}` }, gNodes);
    g.style.color = COLORS[n.type];
    el('circle', { class: 'halo', r: r + 6 }, g);
    el('circle', { class: 'core', r, fill: COLORS[n.type] }, g);
    const t = el('text', { y: r + 18, 'text-anchor': 'middle' }, g); t.textContent = n.label;
    const ty = el('text', { class: 'type', y: r + 31, 'text-anchor': 'middle' }, g); ty.textContent = n.type;
    n.g = g; n.r = r;
  });

  function edgePath(e) {
    const { a, b } = e;
    const dx = b.x - a.x, dy = b.y - a.y, d = Math.hypot(dx, dy) || 1;
    const sx = a.x + dx / d * (a.r + 4), sy = a.y + dy / d * (a.r + 4);
    const tx = b.x - dx / d * (b.r + 6), ty = b.y - dy / d * (b.r + 6);
    // gentle curve off the straight line
    const mx = (sx + tx) / 2 - dy * .12, my = (sy + ty) / 2 + dx * .12;
    return `M${sx},${sy} Q${mx},${my} ${tx},${ty}`;
  }
  function layout() {
    nodes.forEach((n) => n.g.setAttribute('transform', `translate(${n.x},${n.y})`));
    edges.forEach((e) => e.path.setAttribute('d', edgePath(e)));
  }
  layout();

  // ---------- View transform ----------
  const cam = { x: 0, y: 0, k: 1 };
  function apply() {
    const w = host.clientWidth, h = host.clientHeight;
    view.setAttribute('transform', `translate(${w / 2 + cam.x},${h / 2 + cam.y + 20}) scale(${cam.k})`);
    zVal.textContent = Math.round(cam.k * 100) + '%';
  }
  function fit() {
    const w = host.clientWidth, h = host.clientHeight;
    const k = Math.min(w / 860, h / 720, 1.15);
    tweenCam({ x: w > 900 ? 110 : 0, y: 0, k: Math.max(.5, k) });
  }
  function tweenCam(to) {
    if (window.gsap && !S.reduce) gsap.to(cam, { ...to, duration: .8, ease: 'expo.out', onUpdate: apply });
    else { Object.assign(cam, to); apply(); }
  }
  const zoomBy = (f, cx, cy) => {
    const w = host.clientWidth, h = host.clientHeight;
    cx = cx ?? w / 2; cy = cy ?? h / 2;
    const k = Math.min(2.5, Math.max(.35, cam.k * f));
    const ox = cx - (w / 2 + cam.x), oy = cy - (h / 2 + cam.y + 20);
    cam.x -= ox * (k / cam.k - 1); cam.y -= oy * (k / cam.k - 1); cam.k = k;
    apply();
  };
  document.getElementById('z-in').addEventListener('click', () => tweenCam({ k: Math.min(2.5, cam.k * 1.25) }));
  document.getElementById('z-out').addEventListener('click', () => tweenCam({ k: Math.max(.35, cam.k / 1.25) }));
  document.getElementById('z-fit').addEventListener('click', fit);
  host.addEventListener('wheel', (e) => {
    e.preventDefault();
    const r = host.getBoundingClientRect();
    zoomBy(Math.exp(-e.deltaY * .0015), e.clientX - r.left, e.clientY - r.top);
  }, { passive: false });
  addEventListener('resize', apply);

  // ---------- Drag (canvas pan or node move) ----------
  let drag = null;
  host.addEventListener('pointerdown', (e) => {
    if (e.target.closest('.graph__zoom, .graph__dirs')) return;
    const g = e.target.closest('.g-node');
    const n = g && nodes.find((x) => x.g === g);
    drag = { n, sx: e.clientX, sy: e.clientY, ox: n ? n.x : cam.x, oy: n ? n.y : cam.y, moved: false };
    host.setPointerCapture(e.pointerId);
    if (!n) host.classList.add('is-panning');
  });
  host.addEventListener('pointermove', (e) => {
    if (!drag) return;
    const dx = e.clientX - drag.sx, dy = e.clientY - drag.sy;
    if (Math.abs(dx) + Math.abs(dy) > 3) drag.moved = true;
    if (drag.n) { drag.n.x = drag.ox + dx / cam.k; drag.n.y = drag.oy + dy / cam.k; layout(); }
    else { cam.x = drag.ox + dx; cam.y = drag.oy + dy; apply(); }
  });
  host.addEventListener('pointerup', () => {
    if (drag && drag.n && !drag.moved) select(drag.n.id);
    drag = null;
    host.classList.remove('is-panning');
  });
  gNodes.addEventListener('keydown', (e) => {
    if (e.key !== 'Enter' && e.key !== ' ') return;
    const n = nodes.find((x) => x.g === e.target);
    if (n) { e.preventDefault(); select(n.id); }
  });

  // ---------- Selection ----------
  let sel = null;
  function select(id, scroll) {
    const n = byId[id];
    if (!n) return;
    sel = id;
    const linked = new Set([id]);
    edges.forEach((e) => { if (e.a.id === id) linked.add(e.b.id); if (e.b.id === id) linked.add(e.a.id); });
    nodes.forEach((x) => { x.g.classList.toggle('is-sel', x.id === id); x.g.classList.toggle('is-dim', !linked.has(x.id)); });
    edges.forEach((e) => {
      const hot = e.a.id === id || e.b.id === id;
      e.path.classList.toggle('is-hot', hot);
      e.path.classList.toggle('is-dim', !hot);
    });
    renderDetail(n);
    if (scroll) host.scrollIntoView({ behavior: 'smooth', block: 'center' });
  }
  function renderDetail(n) {
    const d = n.detail;
    const links = edges.filter((e) => e.a.id === n.id || e.b.id === n.id).map((e) => (e.a.id === n.id ? e.b : e.a));
    const html = `<div class="detail__swap">
      <div class="detail__kind">${esc(d.kind)}</div>
      <h3 class="detail__title">${esc(d.title)}</h3>
      <dl class="kv">${d.rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join('')}</dl>
      <p class="detail__text">${esc(d.text)}</p>
      <div class="panel__label" style="padding:18px 0 8px">Connected</div>
      <div style="display:flex;flex-wrap:wrap;gap:6px">${links.map((l) => `<button type="button" class="chip" data-go="${esc(l.id)}">${esc(l.label)}</button>`).join('')}</div>
    </div>`;
    const old = detail.firstElementChild;
    if (old && window.gsap && !S.reduce) {
      gsap.to(old, { y: -14, opacity: 0, duration: .22, ease: 'power2.in', onComplete() {
        detail.innerHTML = html;
        gsap.from(detail.firstElementChild, { y: 18, opacity: 0, duration: .6, ease: 'expo.out' });
      } });
    } else detail.innerHTML = html;
  }
  detail.addEventListener('click', (e) => { const b = e.target.closest('[data-go]'); if (b) select(b.dataset.go); });
  document.querySelectorAll('[data-node]').forEach((a) => a.addEventListener('click', (e) => { e.preventDefault(); select(a.dataset.node, true); }));

  document.getElementById('pdf').addEventListener('click', () => {
    if (analysisId && graph !== window.SentinelData.graph) location.href = API.reportUrl(analysisId);
    else window.print();
  });

  // ---------- Entrance ----------
  apply();
  select('sample');
  S.ready.then(() => {
    fit();
    document.querySelectorAll('[data-count]').forEach((c) => {
      const to = +c.dataset.count;
      if (!window.gsap) { c.textContent = to; return; }
      gsap.to({ v: 0 }, { v: to, duration: 1.6, ease: 'expo.out', delay: .2, onUpdate() { c.textContent = Math.round(this.targets()[0].v); } });
    });
    if (!window.gsap || S.reduce) return;
    gsap.from('.graph-wrap > *', { y: 30, opacity: 0, duration: 1, ease: 'expo.out', stagger: .08 });
    nodes.forEach((n, i) => gsap.from(n.g.querySelector('.core'), { attr: { r: 0 }, duration: .9, ease: 'back.out(2)', delay: .3 + i * .07 }));
    edges.forEach((e, i) => {
      const len = e.path.getTotalLength();
      e.path.style.strokeDasharray = len;
      e.path.style.strokeDashoffset = len;
      gsap.to(e.path, { strokeDashoffset: 0, duration: 1.25, ease: 'expo.inOut', delay: .5 + i * .06, onComplete() { e.path.style.strokeDasharray = ''; } });
    });
  });
})();
