/* SentinelTI — Attack Graph page: loads a real analysis (or the example) into the motion engine. */
(async function () {
  const S = window.Sentinel;
  const API = window.SentinelAPI;
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const analysisId = new URLSearchParams(location.search).get('id');
  const detail = document.getElementById('detail');
  const stage = document.getElementById('graph');
  const steps = document.querySelectorAll('#agent-steps li');

  let graph = window.SentinelData.graph;
  let risk = 94;
  let isReal = false;

  // ---------- A real report, when the URL names one ----------
  function fillHeader(a) {
    const r = a.result || {};
    const iocs = r.iocs || {};
    const t = r.triage || {};
    document.querySelector('.ghead h1').textContent = a.filename;
    document.title = a.filename + ' | SentinelTI';
    document.querySelector('.ghead__meta').innerHTML = [
      `<span class="chip" data-tone="${esc(a.tone)}"><span class="dot"></span>${esc(a.verdict)}</span>`,
      a.family ? `<span class="chip">${esc(a.family)}</span>` : '',
      t.label ? `<span class="chip">${esc(t.label)}</span>` : '',
      `<span class="chip mono" title="${esc(a.sha256)}">${esc(a.sha256.slice(0, 12))}…</span>`,
    ].join('');
    const counts = document.querySelectorAll('.ghead__stats [data-count]');
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
      const [analysis, realGraph] = await Promise.all([API.get(analysisId), API.graph(analysisId)]);
      graph = realGraph;
      risk = analysis.risk ?? 50;
      isReal = true;
      fillHeader(analysis);
      const back = document.getElementById('graph-back');
      back.href = 'analyse.html?id=' + encodeURIComponent(analysisId);
      back.textContent = 'Back';
    } catch (err) {
      if (err.status === 401) { location.href = API.loginUrl(); return; }
      if (err.status === 409) { location.href = 'analyse.html?id=' + encodeURIComponent(analysisId); return; }
      S.toast(err.status === 404 ? 'That report was not found, so this is the example' : err.message);
    }
  }

  // ---------- Detail panel ----------
  function renderDetail(node, neighbours) {
    const d = node.source.detail;
    const html = `<div class="detail__swap">
      <div class="detail__kind">${esc(d.kind)}</div>
      <h3 class="detail__title">${esc(d.title)}</h3>
      <dl class="kv">${d.rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join('')}</dl>
      <p class="detail__text">${esc(d.text)}</p>
      <div class="panel__label" style="padding:18px 0 8px">Connected</div>
      <div class="detail__links">${neighbours.map((l) => `<button type="button" class="chip" data-go="${esc(l.id)}">${esc(l.label)}</button>`).join('')}</div>
    </div>`;
    const old = detail.firstElementChild;
    if (old && window.gsap && !S.reduce) {
      gsap.to(old, { y: -14, opacity: 0, filter: 'blur(8px)', duration: .22, ease: 'power2.in', onComplete() {
        detail.innerHTML = html;
        gsap.from(detail.firstElementChild, { y: 18, opacity: 0, filter: 'blur(10px)', duration: .7, ease: 'expo.out', clearProps: 'filter' });
      } });
    } else detail.innerHTML = html;
  }
  detail.addEventListener('click', (e) => { const b = e.target.closest('[data-go]'); if (b) engine.select(b.dataset.go); });

  // ---------- Engine ----------
  const zoomValue = document.getElementById('z-val');
  const stepsBox = document.getElementById('agent-steps');
  const wide = () => innerWidth > 1100;
  const engine = window.SentinelGraph.create(document.getElementById('graph-host'), {
    graph, risk,
    insets: () => (wide() ? { left: 80, right: 376, top: 120, bottom: 70 } : { left: 0, right: 0, top: 20, bottom: 60 }),
    onSelect: renderDetail,
    onZoom: (z) => { const v = Math.round(z * 100) + '%'; if (zoomValue.textContent !== v) zoomValue.textContent = v; },
    onStage: (i) => {
      steps.forEach((li, k) => {
        li.classList.toggle('is-on', k === i);
        li.classList.toggle('is-done', k < i);
      });
      stepsBox.classList.remove('is-rest');
    },
    onDone: () => { steps.forEach((li) => { li.classList.remove('is-on'); li.classList.add('is-done'); }); stepsBox.classList.add('is-rest'); },
  });
  const core = engine.nodes.find((n) => n.type === 'sample') || engine.nodes[0];
  renderDetail(core, engine.neighbours(core.id));

  document.getElementById('z-in').addEventListener('click', () => engine.zoomBy(1.25));
  document.getElementById('z-out').addEventListener('click', () => engine.zoomBy(.8));
  document.getElementById('z-fit').addEventListener('click', () => engine.fit());
  document.getElementById('replay').addEventListener('click', () => engine.replay());
  document.getElementById('pdf').addEventListener('click', () => {
    if (isReal) location.href = API.reportUrl(analysisId);
    else S.toast('This is an example. Analyse a sample to get a real PDF report.');
  });
  document.querySelectorAll('[data-node]').forEach((a) => a.addEventListener('click', (e) => {
    e.preventDefault();
    engine.select(a.dataset.node);
    if (S.lenis) S.lenis.scrollTo(stage, { duration: 1.1 }); else stage.scrollIntoView({ behavior: S.reduce ? 'auto' : 'smooth' });
  }));

  // ---------- Entrance ----------
  document.querySelectorAll('.ghead__stats [data-count]').forEach((c) => {
    const to = +c.dataset.count;
    if (!window.gsap || S.reduce) { c.textContent = to; return; }
    gsap.to({ v: 0 }, { v: to, duration: 2.4, ease: 'expo.out', delay: .4, onUpdate() { c.textContent = Math.round(this.targets()[0].v); } });
  });
  if (window.gsap && !S.reduce) {
    gsap.from('.ghead > *', { y: 24, opacity: 0, filter: 'blur(12px)', duration: 1.1, ease: 'expo.out', stagger: .08, clearProps: 'filter' });
    gsap.from('.detail', { x: 40, opacity: 0, duration: 1.2, ease: 'expo.out', delay: .3, clearProps: 'all' });
  }
})();
