/* SentinelTI — Analyse workspace. Uploads to the backend and follows the five agents live. */
(function () {
  const { agents } = window.SentinelData;
  const S = window.Sentinel;
  const API = window.SentinelAPI;
  const $ = (s) => document.querySelector(s);
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  const thread = $('#thread');
  const dz = $('#dropzone');
  const fileInput = $('#file-input');
  const todo = $('#todo');
  const ctx = $('#ctx');
  const runState = $('#run-state');
  const openGraph = $('#open-graph');
  const EMPTY_CTX = '<p class="ctx__empty" style="padding:0">No sample yet. Drop a file to begin — the Triage Agent fingerprints it before anything else runs.</p>';

  let sessions = [];
  let current = null;      // id of the analysis on screen
  let currentDone = false; // its report and graph exist
  let stream = null;
  let cards = {};
  let stallTimer = null;
  const WAIT_FOR_WORKER_MS = 60000;  // a healthy worker picks a job up within seconds
  const WAIT_FOR_PROGRESS_MS = 300000; // longer than the slowest single tool or LLM call

  // ---------- To-do ----------
  const tick = '<svg viewBox="0 0 12 12" fill="none" stroke-width="2"><path d="M2.5 6.2 5 8.5l4.5-5"/></svg>';
  function renderTodo() {
    todo.innerHTML = agents.map((a) => `<li data-agent="${a.id}"><span class="box">${tick}</span><span><span class="todo__t">${a.n} · ${a.name}</span><span class="todo__s">${a.out}</span></span></li>`).join('');
  }
  function setTodo(id, state) {
    const li = todo.querySelector(`[data-agent="${id}"]`);
    if (!li) return;
    li.classList.toggle('is-run', state === 'run');
    li.classList.toggle('is-done', state === 'done');
  }
  function setRun(label, tone) {
    runState.textContent = label;
    if (tone) runState.dataset.tone = tone; else delete runState.dataset.tone;
  }

  // ---------- Sessions ----------
  const toneColor = { crit: 'var(--signal)', warn: 'var(--signal-amber)', ok: 'var(--signal-ok)' };
  function ago(iso) {
    const s = Math.max(1, (Date.now() - new Date(iso)) / 1000);
    if (s < 60) return 'just now';
    if (s < 3600) return Math.floor(s / 60) + 'm ago';
    if (s < 86400) return Math.floor(s / 3600) + 'h ago';
    return Math.floor(s / 86400) + 'd ago';
  }
  function sessionMeta(a) {
    if (a.status === 'failed') return 'Failed · ' + ago(a.created_at);
    if (a.status !== 'completed') return 'Analysing…';
    return (a.family || a.verdict) + ' · ' + ago(a.created_at);
  }
  function renderSessions() {
    const list = $('#sessions');
    if (!sessions.length) {
      list.innerHTML = '<li><p class="ctx__empty" style="padding:8px 12px">Your analyses appear here.</p></li>';
      return;
    }
    list.innerHTML = sessions.map((a) => `
      <li><button type="button" class="session" data-id="${esc(a.id)}" aria-current="${current === a.id}">
        <span class="session__file">${esc(a.filename)}</span><span class="session__meta">${esc(sessionMeta(a))}</span>
        <span class="session__dot" style="background:${toneColor[a.tone] || 'var(--on-surface-muted)'}"></span>
      </button></li>`).join('');
  }
  async function refreshSessions() {
    try {
      sessions = (await API.list(50)).items;
      renderSessions();
    } catch (err) { handleApiError(err); }
  }
  $('#sessions').addEventListener('click', (e) => {
    const b = e.target.closest('.session');
    if (b) open(b.dataset.id);
  });

  function stopStream() {
    clearTimeout(stallTimer);
    if (stream) { stream.close(); stream = null; }
  }
  function clearStage() {
    stopStream();
    cards = {};
    thread.innerHTML = '';
    renderTodo();
  }
  function reset() {
    clearStage();
    current = null;
    currentDone = false;
    dz.classList.remove('is-gone');
    ctx.innerHTML = EMPTY_CTX;
    openGraph.href = 'report.html';
    setRun('Idle');
    history.replaceState(null, '', 'analyse.html');
    renderSessions();
  }
  $('#new-session').addEventListener('click', reset);

  function handleApiError(err) {
    if (err.status === 401) { location.href = API.loginUrl(); return; }
    S.toast(err.message);
  }

  // ---------- Thread helpers ----------
  function push(html) {
    const el = document.createElement('div');
    el.className = 'msg';
    el.innerHTML = html;
    thread.appendChild(el);
    if (window.gsap && !S.reduce) gsap.from(el, { y: 18, opacity: 0, duration: .7, ease: 'expo.out' });
    thread.scrollTo({ top: thread.scrollHeight, behavior: 'smooth' });
    return el;
  }
  function userMsg(text) {
    push(`<div class="bubble">${esc(text)}</div>`).classList.add('msg--user');
  }
  function infoCard(n, title, bodyHtml, status) {
    const chip = status ? `<span class="card__status chip" data-tone="${status.tone}"><span class="dot"></span>${esc(status.label)}</span>` : '';
    return push(`<div class="card"><div class="card__head"><span class="card__n">${esc(n)}</span><span class="card__title">${esc(title)}</span>${chip}</div>${bodyHtml}</div>`);
  }
  function agentCard(a) {
    const el = push(`<div class="card">
      <div class="card__head"><span class="card__n">${a.n}</span><span class="card__title">${a.name}</span>
        <span class="card__status chip"><span class="spinner"></span>Running</span></div>
      <ul class="card__log"></ul><div class="progress"><i></i></div></div>`);
    const log = el.querySelector('.card__log');
    const bar = el.querySelector('.progress i');
    let filled = .08;
    return {
      line(text) {
        const li = document.createElement('li');
        li.innerHTML = `<span>${esc(text)}</span>`;
        log.appendChild(li);
        if (window.gsap && !S.reduce) gsap.from(li, { opacity: 0, x: -6, duration: .4, ease: 'expo.out' });
        thread.scrollTo({ top: thread.scrollHeight, behavior: 'smooth' });
      },
      bump() {
        filled = Math.min(.92, filled + (1 - filled) * .3);
        bar.style.transition = 'transform .5s cubic-bezier(.22,1,.36,1)';
        bar.style.transform = `scaleX(${filled})`;
      },
      done(label, tone) {
        const st = el.querySelector('.card__status');
        st.innerHTML = `<span class="dot"></span>${esc(label || 'Done')}`;
        st.dataset.tone = tone || 'ok';
        bar.style.transform = 'scaleX(1)';
        setTimeout(() => { el.querySelector('.progress').style.opacity = 0; }, 600);
      },
    };
  }
  const cardFor = (id) => {
    if (!cards[id]) {
      const a = agents.find((x) => x.id === id);
      if (!a) return null;
      cards[id] = agentCard(a);
    }
    return cards[id];
  };

  // ---------- Live events ----------
  function onEvent(id, ev) {
    if (id !== current) return;
    const card = ev.agent ? cardFor(ev.agent) : null;
    switch (ev.type) {
      case 'agent_started':
        setTodo(ev.agent, 'run');
        card && card.bump();
        break;
      case 'tool_call':
        card && card.bump();
        break;
      case 'tool_result':
        card && card.line(ev.line);
        card && card.bump();
        break;
      case 'tool_error':
        card && card.line(`An agent’s call to ${ev.tool} was rejected by validation`);
        break;
      case 'agent_finished':
        card && card.done(ev.label, ev.tone);
        setTodo(ev.agent, 'done');
        break;
      case 'analysis_completed':
      case 'analysis_failed':
        stopStream();
        showFinished(id);
        refreshSessions();
        break;
      default:
    }
  }
  function follow(id) {
    stopStream();
    stream = new EventSource(API.eventsUrl(id));
    let started = false;
    let notice = null;
    // Nothing else tells the analyst that a job is stuck, for example because no worker is running.
    const watch = () => {
      clearTimeout(stallTimer);
      stallTimer = setTimeout(() => {
        if (id !== current || notice) return;
        notice = started
          ? infoCard('!', 'No progress for a while', '<p style="margin:0">The agents have gone quiet. This run continues by itself if the worker recovers.</p>', { tone: 'warn', label: 'Waiting' })
          : infoCard('!', 'Waiting for a worker', '<p style="margin:0">Your file is safely queued, but no worker has picked it up. Check that the worker is running. The analysis starts by itself once it is.</p>', { tone: 'warn', label: 'Queued' });
      }, started ? WAIT_FOR_PROGRESS_MS : WAIT_FOR_WORKER_MS);
    };
    watch();
    stream.onmessage = (m) => {
      if (notice) { notice.remove(); notice = null; }
      started = true;
      watch();
      try { onEvent(id, JSON.parse(m.data)); } catch (e) { /* a malformed event is not worth failing the page */ }
    };
    // The stream ended without a final event, for example because it expired.
    stream.addEventListener('end', () => { if (stream) { stopStream(); showFinished(id); } });
  }

  // ---------- Results ----------
  function humanSize(n) {
    return n > 1048576 ? (n / 1048576).toFixed(2) + ' MB' : (n / 1024).toFixed(1) + ' KB';
  }
  function renderContext(a) {
    const r = a.result || {};
    const t = r.triage || {};
    const techniques = r.techniques || [];
    const iocs = r.iocs || {};
    const net = [...(iocs.urls || []), ...(iocs.ips || [])].slice(0, 5);
    const modes = { llm: 'LLM + tools', degraded: 'Tools (LLM failed)', deterministic: 'Tools only' };
    ctx.innerHTML = `<dl class="kv">
      <dt>File</dt><dd>${esc(a.filename)}</dd>
      ${t.label ? `<dt>Type</dt><dd>${esc(t.label)}</dd>` : ''}
      <dt>Size</dt><dd>${humanSize(a.size_bytes)}</dd>
      ${t.entropy !== undefined ? `<dt>Entropy</dt><dd>${esc(t.entropy)}</dd>` : ''}
      <dt>SHA-256</dt><dd class="mono" title="${esc(a.sha256)}">${esc(a.sha256.slice(0, 16))}…</dd>
      ${a.family ? `<dt>Family</dt><dd>${esc(a.family)}</dd>` : ''}
      ${a.verdict ? `<dt>Verdict</dt><dd>${esc(a.verdict)} · ${esc(a.risk)}</dd>` : ''}
      ${a.llm_mode ? `<dt>Agents</dt><dd>${esc(modes[a.llm_mode] || a.llm_mode)}</dd>` : ''}
      ${techniques.length ? `<dt>ATT&amp;CK</dt><dd>${techniques.map((x) => esc(x.id)).join(', ')}</dd>` : ''}
      ${net.length ? `<dt>Network</dt><dd class="mono">${net.map(esc).join('<br>')}</dd>` : ''}
    </dl>`;
  }
  function showVerdict(a) {
    const r = a.result || {};
    const narrative = r.narrative || {};
    const points = (narrative.summary || []).map((p) => `<li><span>${esc(p.text)}</span></li>`).join('');
    const actions = (narrative.recommended_actions || []).map((x) => `<li><span>${esc(x)}</span></li>`).join('');
    const unproven = (r.hypotheses || []).map((h) => `<li><span>${esc(h.statement)}</span></li>`).join('');
    const warnings = (r.warnings || []).map((w) => `<li><span>${esc(w)}</span></li>`).join('');
    const block = (title, items) => (items ? `<div class="verdict__label" style="margin-top:14px">${title}</div><ul class="card__log" style="margin-top:6px">${items}</ul>` : '');
    const el = push(`<div class="verdict">
      <div class="verdict__top"><div><div class="verdict__label">Verdict</div><div class="verdict__value">${esc(a.verdict)}</div></div>
      <div style="text-align:right"><div class="verdict__label">Risk</div><div class="verdict__score" data-count>0</div></div></div>
      ${block('Why', points)}${block('Recommended actions', actions)}${block('Unproven, not scored', unproven)}${block('Warnings', warnings)}
      <div class="actions"><a class="glass-cta" data-emph="primary" href="report.html?id=${esc(a.id)}" data-swap="Open Attack Graph">Open Attack Graph</a>
      <a class="glass-cta" href="${esc(API.reportUrl(a.id))}" data-swap="Download PDF">Download PDF</a></div></div>`);
    S.applySwaps(el);
    const n = el.querySelector('[data-count]');
    if (window.gsap) gsap.to({ v: 0 }, { v: a.risk, duration: 1.4, ease: 'expo.out', onUpdate() { n.textContent = Math.round(this.targets()[0].v); } });
    else n.textContent = a.risk;
  }
  async function showFinished(id) {
    let a;
    try { a = await API.get(id); } catch (err) { handleApiError(err); return; }
    if (id !== current) return;
    renderContext(a);
    if (a.status === 'failed') {
      Object.values(cards).forEach((c) => c.done('Stopped', 'warn'));
      infoCard('!', 'Analysis failed', `<p style="margin:0">${esc(a.error || 'The analysis could not finish.')}</p>`, { tone: 'crit', label: 'Failed' });
      setRun('Failed', 'crit');
      return;
    }
    if (a.status !== 'completed') return;
    currentDone = true;
    openGraph.href = 'report.html?id=' + encodeURIComponent(a.id);
    agents.forEach((x) => setTodo(x.id, 'done'));
    showVerdict(a);
    setRun(a.verdict, a.tone);
  }
  function renderTrace(a) {
    // One card per agent, rebuilt from the stored trace of a finished run.
    const merged = {};
    ((a.result || {}).trace || []).forEach((t) => {
      merged[t.agent] = merged[t.agent] || { lines: [], label: t.label, tone: t.tone };
      merged[t.agent].lines.push(...t.lines);
    });
    agents.forEach((x) => {
      if (!merged[x.id]) return;
      const card = agentCard(x);
      merged[x.id].lines.forEach((l) => card.line(l));
      card.done(merged[x.id].label, merged[x.id].tone);
    });
  }
  async function open(id) {
    clearStage();
    current = id;
    currentDone = false;
    dz.classList.add('is-gone');
    history.replaceState(null, '', 'analyse.html?id=' + encodeURIComponent(id));
    renderSessions();
    let a;
    try { a = await API.get(id); } catch (err) {
      if (err.status === 404) { S.toast('That analysis was not found'); reset(); return; }
      handleApiError(err);
      return;
    }
    if (id !== current) return;
    userMsg('Analyse ' + a.filename);
    renderContext(a);
    if (a.status === 'completed' || a.status === 'failed') {
      renderTrace(a);
      showFinished(id);
    } else {
      setRun('Running', 'warn');
      follow(id);
    }
  }

  // ---------- Upload ----------
  async function analyse(file) {
    clearStage();
    current = null;
    dz.classList.add('is-gone');
    userMsg('Analyse ' + file.name);
    setRun('Uploading', 'warn');
    let created;
    try {
      created = await API.upload(file);
    } catch (err) {
      if (err.status === 401) { handleApiError(err); return; }
      infoCard('!', 'Upload failed', `<p style="margin:0">${esc(err.message)}</p>`, { tone: 'crit', label: 'Failed' });
      setRun('Idle');
      return;
    }
    current = created.id;
    currentDone = false;
    history.replaceState(null, '', 'analyse.html?id=' + encodeURIComponent(created.id));
    sessions.unshift(created);
    renderSessions();
    renderContext(created);
    setRun('Running', 'warn');
    follow(created.id);
  }

  // ---------- Input: drop, pick, paste, composer ----------
  dz.addEventListener('click', () => fileInput.click());
  $('#attach').addEventListener('click', () => fileInput.click());
  fileInput.addEventListener('change', () => { if (fileInput.files[0]) analyse(fileInput.files[0]); fileInput.value = ''; });
  ['dragenter', 'dragover'].forEach((t) => document.addEventListener(t, (e) => { e.preventDefault(); dz.classList.add('is-over'); }));
  ['dragleave', 'drop'].forEach((t) => document.addEventListener(t, (e) => {
    e.preventDefault();
    if (t === 'dragleave' && e.relatedTarget) return;
    dz.classList.remove('is-over');
    if (t === 'drop' && e.dataTransfer.files[0]) analyse(e.dataTransfer.files[0]);
  }));
  document.addEventListener('paste', (e) => {
    const f = e.clipboardData && e.clipboardData.files[0];
    if (f) { e.preventDefault(); analyse(f); return; }
    const t = (e.clipboardData.getData('text') || '').trim();
    if (/^[a-f0-9]{64}$/i.test(t) && document.activeElement !== $('#prompt')) { e.preventDefault(); hashLookup(t); }
  });

  async function hashLookup(hash) {
    dz.classList.add('is-gone');
    userMsg('Look up ' + hash);
    let res;
    try { res = await API.lookup(hash); } catch (err) { handleApiError(err); return; }
    const vt = res.reputation.virustotal, otx = res.reputation.otx;
    const describe = (name, x, found) => ({
      not_configured: `${name}: no API key configured yet`,
      unknown: `${name}: this hash is not known`,
      error: `${name}: the lookup failed, try again later`,
      found: found,
    }[x.status]);
    const lines = [
      describe('VirusTotal', vt, `VirusTotal: ${vt.malicious} engines flag this hash${vt.label ? ' · ' + vt.label : ''}`),
      describe('AlienVault OTX', otx, `AlienVault OTX: ${otx.pulse_count} threat pulses`),
    ].map((l) => `<li><span>${esc(l)}</span></li>`);
    res.previous_analyses.forEach((a) => {
      lines.push(`<li><span>You analysed this as <a href="analyse.html?id=${esc(a.id)}">${esc(a.filename)}</a> (${esc(a.verdict || a.status)})</span></li>`);
    });
    if (!res.previous_analyses.length) lines.push('<li><span>You have not analysed this hash before</span></li>');
    infoCard('04', 'Threat Context Agent', `<ul class="card__log">${lines.join('')}</ul>`);
  }

  $('#composer').addEventListener('submit', async (e) => {
    e.preventDefault();
    const inp = $('#prompt');
    const q = inp.value.trim();
    if (!q) return;
    inp.value = '';
    if (/^[a-f0-9]{64}$/i.test(q)) { hashLookup(q); return; }
    dz.classList.add('is-gone');
    userMsg(q);
    const title = 'Explainability Agent';
    if (!current || !currentDone) {
      infoCard('05', title, `<p style="margin:0">${current ? 'The agents are still working. Ask again when the verdict is in.' : 'Drop a sample first. I answer from the evidence the five agents collect, not from guesses.'}</p>`);
      return;
    }
    const el = infoCard('05', title, '<p style="margin:0;line-height:1.55"><span class="spinner"></span></p>');
    const body = el.querySelector('p');
    try {
      const res = await API.chat(current, q);
      body.textContent = res.answer;
      thread.scrollTo({ top: thread.scrollHeight, behavior: 'smooth' });
    } catch (err) {
      if (err.status === 401) { handleApiError(err); return; }
      body.textContent = err.message;
    }
  });

  $('#pdf').addEventListener('click', () => {
    if (current && currentDone) location.href = API.reportUrl(current);
    else S.toast('Analyse a sample first');
  });

  // ---------- Start ----------
  renderTodo();
  renderSessions();
  if (window.gsap && !S.reduce) {
    S.ready.then(() => gsap.from('.workspace > .panel', { y: 30, opacity: 0, duration: 1, ease: 'expo.out', stagger: .08 }));
  }
  API.me().then(async () => {
    await refreshSessions();
    const id = new URLSearchParams(location.search).get('id');
    if (id) open(id);
  }).catch((err) => {
    if (err.status === 401) { location.href = API.loginUrl(); return; }
    setRun('Offline', 'crit');
    S.toast('Can’t reach the analysis server');
  });
})();
