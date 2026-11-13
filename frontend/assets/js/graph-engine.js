/* SentinelTI — attack graph motion engine (canvas 2D, no dependencies).
   The sample is a live core. Evidence orbits it on tilted rings, grouped by what kind of
   finding it is, and data pulses along the links. The intro replays the analysis: each
   agent's findings fly out of the core in the order they were produced. */
window.SentinelGraph = (function () {
  const TAU = Math.PI * 2;
  const clamp = (v, a, b) => Math.max(a, Math.min(b, v));
  const lerp = (a, b, t) => a + (b - a) * t;
  const damp = (cur, to, k, dt) => lerp(cur, to, 1 - Math.exp(-k * dt));
  const outExpo = (t) => (t >= 1 ? 1 : 1 - Math.pow(2, -10 * t));
  const outBack = (t) => { const x = t - 1; return 1 + 2.7 * x * x * x + 1.7 * x * x; };

  const STYLE = {
    sample: { rgb: [255, 238, 220], r: 14 },
    evidence: { rgb: [255, 176, 64], r: 8 },
    network: { rgb: [255, 224, 130], r: 9 },
    capability: { rgb: [255, 86, 22], r: 9.5 },
    intel: { rgb: [255, 208, 174], r: 7.5 },
  };
  const RINGS = {
    evidence: { r: 150, tx: .3, tz: .38, w: -.055 },
    network: { r: 205, tx: -.26, tz: -.42, w: .04 },
    capability: { r: 268, tx: .08, tz: -.1, w: .026 },
    intel: { r: 352, tx: -.07, tz: .14, w: -.016 },
  };
  const AGENT_ORDER = [['evidence', 'network'], ['capability'], ['intel']];
  const MARK = 'M122 165 228 222 332 165 332 228 395 228 330 333 395 438 332 438 332 500 228 440 122 500 122 438 58 438 125 333 58 228 122 228ZM125 232 170 333 125 435 228 378 330 435 285 333 330 232 228 290Z';

  // Soft light sprites, drawn additively. Far cheaper than canvas shadows or filters.
  const spriteCache = new Map();
  function sprite(rgb, hot) {
    const key = rgb.join() + (hot ? 'h' : '');
    if (spriteCache.has(key)) return spriteCache.get(key);
    const c = document.createElement('canvas');
    c.width = c.height = 128;
    const x = c.getContext('2d');
    const g = x.createRadialGradient(64, 64, 0, 64, 64, 64);
    const col = (a) => `rgba(${rgb[0]},${rgb[1]},${rgb[2]},${a})`;
    if (hot) { g.addColorStop(0, 'rgba(255,252,246,1)'); g.addColorStop(.14, col(.95)); g.addColorStop(.4, col(.26)); }
    else { g.addColorStop(0, col(.9)); g.addColorStop(.2, col(.42)); g.addColorStop(.5, col(.1)); }
    g.addColorStop(1, col(0));
    x.fillStyle = g;
    x.fillRect(0, 0, 128, 128);
    spriteCache.set(key, c);
    return c;
  }

  function create(host, opts) {
    const options = { labels: true, interactive: true, compact: false, risk: 50, insets: () => ({ left: 0, right: 0, top: 0, bottom: 0 }), ...opts };
    const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;
    const canvas = document.createElement('canvas');
    canvas.className = 'g-canvas';
    canvas.setAttribute('aria-hidden', 'true');
    host.prepend(canvas);
    const ctx = canvas.getContext('2d', { alpha: false });
    const labelHost = options.labels ? document.createElement('div') : null;
    if (labelHost) { labelHost.className = 'g-labels'; canvas.after(labelHost); }

    const risk = clamp(options.risk, 0, 100) / 100;
    const coreRgb = [255, Math.round(lerp(190, 92, risk)), Math.round(lerp(120, 24, risk))];
    const period = lerp(5, 1.25, risk); // A dangerous sample has a faster heartbeat.

    // ---------- Scene ----------
    const groups = {};
    const nodes = options.graph.nodes.map((source) => {
      const type = STYLE[source.type] ? source.type : 'intel';
      const n = { id: source.id, type, label: source.label, source, style: STYLE[type], x: 0, y: 0, z: 0, sx: 0, sy: 0, ss: 1, sz: 0, r: 0, p: 0, t0: 0, hot: 0, dim: 0, flash: 0, alpha: 1, labelOn: false };
      if (type !== 'sample') (groups[type] = groups[type] || []).push(n);
      return n;
    });
    const byId = Object.fromEntries(nodes.map((n) => [n.id, n]));
    const core = nodes.find((n) => n.type === 'sample') || nodes[0];
    const rings = Object.keys(RINGS).map((type) => ({ type, ...RINGS[type], phase: Math.random() * TAU, comet: Math.random() * TAU, nodes: groups[type] || [], rgb: STYLE[type].rgb }));
    rings.forEach((ring) => ring.nodes.forEach((n, i) => { n.ring = ring; n.theta = (i / ring.nodes.length) * TAU; }));

    const edges = options.graph.edges.filter(([a, b]) => byId[a] && byId[b]).map(([a, b]) => ({
      a: byId[a], b: byId[b], t0: 0, hot: 0, dim: 0, reveal: 0,
      pulses: Array.from({ length: 2 }, (_, i) => (i / 2 + Math.random() * .3) % 1),
      ax: 0, ay: 0, cx: 0, cy: 0, bx: 0, by: 0, depth: 0,
    }));
    const links = new Map(nodes.map((n) => [n.id, new Set()]));
    edges.forEach((e) => { links.get(e.a.id).add(e.b.id); links.get(e.b.id).add(e.a.id); });

    // Background dust scattered through the volume
    const DUST = options.compact ? 90 : 320;
    const dust = new Float32Array(DUST * 4);
    for (let i = 0; i < DUST; i++) {
      const a = Math.random() * TAU, h = Math.acos(2 * Math.random() - 1), r = 240 + Math.random() * 720;
      dust[i * 4] = r * Math.sin(h) * Math.cos(a);
      dust[i * 4 + 1] = r * Math.cos(h) * .6;
      dust[i * 4 + 2] = r * Math.sin(h) * Math.sin(a);
      dust[i * 4 + 3] = .25 + Math.random() * .75;
    }
    const shocks = [];

    // ---------- Timeline: replay what each agent found ----------
    let clock = 0, sweepAt = 0, endAt = 0, stages = [], stageNow = -1, swept = false, finished = false;
    function schedule() {
      core.t0 = .05;
      stages = [{ i: 0, t: 0 }];
      let t = .9;
      AGENT_ORDER.forEach((types, index) => {
        stages.push({ i: index + 1, t });
        types.forEach((type) => (groups[type] || []).forEach((n) => { n.t0 = t; t += .11; }));
        t += .34;
      });
      stages.push({ i: 4, t });
      sweepAt = t; endAt = t + 1.3;
      edges.forEach((e) => { e.t0 = Math.max(e.a.t0, e.b.t0) + .22; });
    }
    schedule();
    function replay() {
      clock = reduce ? endAt + 1 : 0;
      stageNow = -1; swept = reduce; finished = false;
      shocks.length = 0;
    }

    // ---------- Camera ----------
    const cam = { yaw: -.5, pitch: .46, zoom: options.compact ? .86 : .92, yawT: -.5, pitchT: .46, zoomT: options.compact ? .86 : 1, fx: 0, fy: 0, fz: 0, fxT: 0, fyT: 0, fzT: 0, lock: false };
    const baseZoom = cam.zoomT;
    let W = 0, H = 0, DPR = 1, CX = 0, CY = 0, FIT = 1, floorGlow = null;
    let sinY = 0, cosY = 1, sinP = 0, cosP = 1;
    let px = 0, py = 0, ps = 1, pz = 0, ox = 0, oy = 0, oz = 0;

    function camSetup() {
      sinY = Math.sin(cam.yaw); cosY = Math.cos(cam.yaw);
      sinP = Math.sin(cam.pitch); cosP = Math.cos(cam.pitch);
    }
    function project(x, y, z) {
      const dx = x - cam.fx, dy = y - cam.fy, dz = z - cam.fz;
      const x1 = dx * cosY - dz * sinY, z1 = dx * sinY + dz * cosY;
      const y2 = dy * cosP - z1 * sinP, z2 = dy * sinP + z1 * cosP;
      const f = 920 / Math.max(120, 920 + z2);
      ps = f * cam.zoom * FIT; pz = z2;
      px = CX + x1 * ps; py = CY + y2 * ps;
    }
    function ringPoint(ring, angle, radius) {
      const x = radius * Math.cos(angle), z = radius * Math.sin(angle);
      const cz = Math.cos(ring.tz), sz = Math.sin(ring.tz), cx = Math.cos(ring.tx), sx = Math.sin(ring.tx);
      const x1 = x * cz, y1 = x * sz;
      ox = x1; oy = y1 * cx - z * sx; oz = y1 * sx + z * cx;
    }

    function resize() {
      const rect = host.getBoundingClientRect();
      W = Math.max(2, rect.width); H = Math.max(2, rect.height);
      DPR = Math.min(window.devicePixelRatio || 1, quality > 0 ? 2 : 1);
      canvas.width = Math.round(W * DPR); canvas.height = Math.round(H * DPR);
      const inset = options.insets(W, H);
      const availW = W - inset.left - inset.right, availH = H - inset.top - inset.bottom;
      CX = inset.left + availW / 2; CY = inset.top + availH / 2;
      FIT = clamp(Math.min(availW / 780, availH / 540), .36, 1.7);
      floorGlow = null;
    }

    // ---------- Input ----------
    let hover = null, selected = options.compact ? null : core, lastInput = -10, drag = null;
    function pick(mx, my) {
      let best = null, bestD = Infinity;
      nodes.forEach((n) => {
        if (n.p < .6) return;
        const d = Math.hypot(n.sx - mx, n.sy - my);
        if (d < Math.max(n.r + 8, 15) && d < bestD) { best = n; bestD = d; }
      });
      return best;
    }
    function select(id, quiet) {
      const n = byId[id];
      if (!n) return;
      selected = n;
      if (labelHost) nodes.forEach((m) => m.el && m.el.setAttribute('aria-pressed', m === n));
      if (n === core) {
        cam.fxT = cam.fyT = cam.fzT = 0; cam.zoomT = baseZoom;
      } else {
        // Swing the camera round so this node faces the viewer, a little off the core.
        const target = Math.atan2(n.x, n.z) + Math.PI + .6;
        const delta = Math.atan2(Math.sin(target - cam.yaw), Math.cos(target - cam.yaw));
        cam.yawT = cam.yaw + delta; cam.pitchT = .36; cam.lock = true;
        cam.fxT = n.x * .42; cam.fyT = n.y * .42; cam.fzT = n.z * .42; cam.zoomT = baseZoom * 1.2;
      }
      shocks.push({ node: n, t: 0, dur: 1.1, R: n === core ? 120 : 62, rgb: n.style.rgb });
      if (!quiet && options.onSelect) options.onSelect(n, api.neighbours(n.id));
    }
    function zoomBy(f) { cam.zoomT = clamp(cam.zoomT * f, .42, 2.8); lastInput = clock; }
    function fit() { cam.lock = false; cam.pitchT = .46; select(core.id); }

    if (options.interactive) {
      host.addEventListener('pointerdown', (e) => {
        if (e.target.closest('.g-label, button, a, .no-drag')) return;
        drag = { x: e.clientX, y: e.clientY, sx: e.clientX, sy: e.clientY, moved: false, touch: e.pointerType === 'touch' };
        host.setPointerCapture(e.pointerId);
        host.classList.add('is-dragging');
      });
      host.addEventListener('pointermove', (e) => {
        const rect = host.getBoundingClientRect();
        if (drag) {
          const dx = e.clientX - drag.x, dy = e.clientY - drag.y;
          drag.x = e.clientX; drag.y = e.clientY;
          if (Math.abs(e.clientX - drag.sx) + Math.abs(e.clientY - drag.sy) > 4) drag.moved = true;
          cam.lock = false;
          cam.yaw += dx * .0058; cam.yawT = cam.yaw;
          if (!drag.touch) { cam.pitch = clamp(cam.pitch + dy * .004, -.2, 1.25); cam.pitchT = cam.pitch; }
          lastInput = clock;
          return;
        }
        if (e.pointerType === 'mouse' && !e.target.closest('.g-label, button, a, .no-drag')) {
          setHover(pick(e.clientX - rect.left, e.clientY - rect.top));
        }
      });
      const release = (e) => {
        if (!drag) return;
        const rect = host.getBoundingClientRect();
        if (!drag.moved) { const n = pick(e.clientX - rect.left, e.clientY - rect.top); if (n) select(n.id); }
        drag = null;
        host.classList.remove('is-dragging');
      };
      host.addEventListener('pointerup', release);
      host.addEventListener('pointercancel', () => { drag = null; host.classList.remove('is-dragging'); });
      host.addEventListener('pointerleave', () => setHover(null));
      host.addEventListener('wheel', (e) => { e.preventDefault(); zoomBy(Math.exp(-e.deltaY * .0013)); }, { passive: false });
    }
    function setHover(n) {
      if (hover === n) return;
      hover = n;
      host.classList.toggle('is-over', !!n);
    }

    // ---------- Labels ----------
    let labelWidths = false;
    if (labelHost) {
      nodes.forEach((n) => {
        const b = document.createElement('button');
        b.type = 'button';
        b.className = 'g-label';
        b.dataset.type = n.type;
        b.setAttribute('aria-label', `${n.label}, ${n.type}`);
        b.setAttribute('aria-pressed', n === selected);
        const text = document.createElement('span');
        text.textContent = n.label;
        const kind = document.createElement('small');
        kind.textContent = n.type;
        b.append(text, kind);
        b.addEventListener('click', () => select(n.id));
        b.addEventListener('pointerenter', () => setHover(n));
        b.addEventListener('pointerleave', () => setHover(null));
        b.addEventListener('focus', () => setHover(n));
        b.addEventListener('blur', () => setHover(null));
        labelHost.appendChild(b);
        n.el = b;
      });
    }
    let declutterTick = 0;
    function declutter() {
      if (!labelWidths) nodes.forEach((n) => { n.w = n.el.offsetWidth; });
      labelWidths = true;
      const linked = selected ? links.get(selected.id) : new Set();
      const score = (n) => (n === hover ? 5e4 : 0) + (n === selected ? 4e4 : 0) + (linked.has(n.id) ? 2e4 : 0) + (n === core ? 3e4 : 0) - n.sz;
      const order = nodes.slice().sort((a, b) => score(b) - score(a));
      const placed = [];
      order.forEach((n) => {
        const box = { l: n.sx - n.w / 2 - 3, r: n.sx + n.w / 2 + 3, t: n.sy + n.r + 2, b: n.sy + n.r + 22 };
        const clash = placed.some((q) => box.l < q.r && box.r > q.l && box.t < q.b && box.b > q.t);
        n.labelOn = n.p > .75 && !clash;
        if (n.labelOn) placed.push(box);
      });
    }

    // ---------- Drawing ----------
    let t = 0, sweep = 0, beat = 0, shockTimer = 0, quality = reduce ? 1 : 2, slow = 0, frames = 0;

    function drawBackground() {
      ctx.globalCompositeOperation = 'source-over';
      ctx.fillStyle = '#000';
      ctx.fillRect(0, 0, W, H);
      if (!floorGlow) {
        floorGlow = ctx.createRadialGradient(CX, CY, 0, CX, CY, Math.max(W, H) * .62);
        floorGlow.addColorStop(0, `rgba(${coreRgb[0]},${Math.round(coreRgb[1] * .55)},0,${.1 + risk * .12})`);
        floorGlow.addColorStop(.45, 'rgba(70,22,0,.1)');
        floorGlow.addColorStop(1, 'rgba(0,0,0,0)');
      }
      ctx.fillStyle = floorGlow;
      ctx.fillRect(0, 0, W, H);
    }
    function drawDust() {
      ctx.fillStyle = '#ffb27a';
      const stride = quality > 0 ? 1 : 3;
      for (let i = 0; i < DUST; i += stride) {
        const k = i * 4;
        project(dust[k], dust[k + 1], dust[k + 2]);
        if (px < 0 || px > W || py < 0 || py > H) continue;
        const size = dust[k + 3] * ps * 1.5;
        ctx.globalAlpha = clamp(.42 - pz / 1700, .04, .55) * dust[k + 3] * (.7 + .3 * Math.sin(t * .8 + i));
        ctx.fillRect(px, py, size, size);
      }
      ctx.globalAlpha = 1;
    }
    function drawFloor() {
      const y = 262;
      ctx.lineWidth = 1;
      ctx.strokeStyle = 'rgba(255,130,50,.075)';
      ctx.beginPath();
      for (let r = 130; r <= 520; r += 130) {
        for (let i = 0; i <= 56; i++) {
          const a = (i / 56) * TAU;
          project(r * Math.cos(a), y, r * Math.sin(a));
          if (i === 0) ctx.moveTo(px, py); else ctx.lineTo(px, py);
        }
      }
      if (quality > 1) {
        for (let i = 0; i < 18; i++) {
          const a = (i / 18) * TAU;
          project(130 * Math.cos(a), y, 130 * Math.sin(a)); ctx.moveTo(px, py);
          project(520 * Math.cos(a), y, 520 * Math.sin(a)); ctx.lineTo(px, py);
        }
      }
      ctx.stroke();
    }
    function strokeRing(ring, radius, width, front, back, rgb) {
      const STEPS = 96;
      for (let pass = 0; pass < 2; pass++) {
        const isFront = pass === 1;
        ctx.beginPath();
        let open = false;
        for (let i = 0; i <= STEPS; i++) {
          ringPoint(ring, (i / STEPS) * TAU, radius);
          project(ox, oy, oz);
          if ((pz < 0) === isFront) { if (open) ctx.lineTo(px, py); else { ctx.moveTo(px, py); open = true; } } else open = false;
        }
        ctx.lineWidth = width;
        ctx.strokeStyle = `rgba(${rgb[0]},${rgb[1]},${rgb[2]},${isFront ? front : back})`;
        ctx.stroke();
      }
    }
    function drawOrbits() {
      rings.forEach((ring) => {
        if (!ring.nodes.length) return;
        const grow = outExpo(clamp((clock - (ring.nodes[0].t0 - .3)) / 1.2, 0, 1));
        if (grow <= 0) return;
        strokeRing(ring, ring.r * grow, 1, .2 * grow, .07 * grow, ring.rgb);
        if (quality < 1) return;
        // A comet riding each ring
        ring.comet += dtNow * (ring.w > 0 ? .55 : -.42);
        ctx.globalCompositeOperation = 'lighter';
        const glow = sprite(ring.rgb);
        for (let k = 0; k < 10; k++) {
          ringPoint(ring, ring.comet - (ring.w > 0 ? 1 : -1) * k * .022, ring.r * grow);
          project(ox, oy, oz);
          const size = (13 - k) * ps * (pz < 0 ? 1 : .6);
          ctx.globalAlpha = (1 - k / 10) * (pz < 0 ? .85 : .35) * grow;
          ctx.drawImage(glow, px - size / 2, py - size / 2, size, size);
        }
        ctx.globalAlpha = 1;
        ctx.globalCompositeOperation = 'source-over';
      });
    }
    function drawSweep() {
      if (quality < 1 || clock < .4) return;
      const reach = 372, WEDGES = 26, STEP = .034;
      project(0, 0, 0);
      const c0 = px, c1 = py;
      ctx.globalCompositeOperation = 'lighter';
      ctx.fillStyle = `rgb(${coreRgb[0]},${coreRgb[1]},${coreRgb[2]})`;
      for (let i = 0; i < WEDGES; i++) {
        const a = sweep - i * STEP;
        project(reach * Math.cos(a), 0, reach * Math.sin(a));
        const x1 = px, y1 = py;
        project(reach * Math.cos(a - STEP), 0, reach * Math.sin(a - STEP));
        ctx.globalAlpha = .1 * (1 - i / WEDGES) * (.45 + risk * .55);
        ctx.beginPath(); ctx.moveTo(c0, c1); ctx.lineTo(x1, y1); ctx.lineTo(px, py); ctx.closePath(); ctx.fill();
      }
      ctx.globalAlpha = 1;
      ctx.globalCompositeOperation = 'source-over';
    }
    const bez = (a, c, b, u) => (1 - u) * (1 - u) * a + 2 * (1 - u) * u * c + u * u * b;
    function drawEdges() {
      edges.forEach((e) => {
        e.reveal = clamp((clock - e.t0) / .7, 0, 1);
        if (e.reveal <= 0) return;
        const { a, b } = e;
        project(a.x, a.y, a.z); e.ax = px; e.ay = py;
        project(b.x, b.y, b.z); e.bx = px; e.by = py; const s = ps;
        project((a.x + b.x) / 2, (a.y + b.y) / 2 - 26 - Math.hypot(a.x - b.x, a.z - b.z) * .1, (a.z + b.z) / 2);
        e.cx = px; e.cy = py; e.s = s;
        const rev = outExpo(e.reveal);
        const alpha = (.3 + e.hot * .62) * (1 - e.dim * .82);
        const grad = ctx.createLinearGradient(e.ax, e.ay, e.bx, e.by);
        const ca = a.style.rgb, cb = b.style.rgb;
        grad.addColorStop(0, `rgba(${ca[0]},${ca[1]},${ca[2]},${alpha})`);
        grad.addColorStop(1, `rgba(${cb[0]},${cb[1]},${cb[2]},${alpha})`);
        ctx.strokeStyle = grad;
        ctx.lineWidth = (.8 + e.hot * 1.5) * clamp(s, .6, 1.5);
        ctx.beginPath();
        ctx.moveTo(e.ax, e.ay);
        const steps = Math.ceil(18 * rev);
        for (let i = 1; i <= steps; i++) {
          const u = (i / 18) * (rev * 18 / steps > 1 ? 1 : rev * 18 / steps);
          ctx.lineTo(bez(e.ax, e.cx, e.bx, u), bez(e.ay, e.cy, e.by, u));
        }
        ctx.stroke();
      });
      // Pulses, drawn additively on top of every link
      ctx.globalCompositeOperation = 'lighter';
      edges.forEach((e) => {
        if (e.reveal <= 0) return;
        const glow = sprite(e.b.style.rgb, true);
        if (e.reveal < 1) {
          const u = outExpo(e.reveal), size = 26 * (e.s || 1);
          ctx.globalAlpha = 1;
          ctx.drawImage(glow, bez(e.ax, e.cx, e.bx, u) - size / 2, bez(e.ay, e.cy, e.by, u) - size / 2, size, size);
          return;
        }
        const speed = (.16 + risk * .16) * (1 + e.hot * 1.5);
        const trail = quality > 0 ? 6 : 1;
        for (let p = 0; p < e.pulses.length; p++) {
          e.pulses[p] = (e.pulses[p] + dtNow * speed) % 1;
          for (let k = 0; k < trail; k++) {
            const u = e.pulses[p] - k * .018;
            if (u < 0) continue;
            const size = (11 + e.hot * 7 - k * 1.5) * (e.s || 1);
            ctx.globalAlpha = (1 - k / trail) * (.75 + e.hot * .25) * (1 - e.dim * .88);
            ctx.drawImage(glow, bez(e.ax, e.cx, e.bx, u) - size / 2, bez(e.ay, e.cy, e.by, u) - size / 2, size, size);
          }
        }
      });
      ctx.globalAlpha = 1;
      ctx.globalCompositeOperation = 'source-over';
    }
    function glyph(n, r) {
      ctx.beginPath();
      if (n.type === 'capability') {
        for (let i = 0; i < 6; i++) { const a = i / 6 * TAU + TAU / 12; ctx[i ? 'lineTo' : 'moveTo'](n.sx + r * Math.cos(a), n.sy + r * Math.sin(a)); }
        ctx.closePath();
      } else if (n.type === 'evidence') {
        ctx.moveTo(n.sx, n.sy - r * 1.15); ctx.lineTo(n.sx + r * 1.15, n.sy); ctx.lineTo(n.sx, n.sy + r * 1.15); ctx.lineTo(n.sx - r * 1.15, n.sy); ctx.closePath();
      } else if (n.type === 'intel') {
        for (let i = 0; i < 3; i++) { const a = i / 3 * TAU - Math.PI / 2; ctx[i ? 'lineTo' : 'moveTo'](n.sx + r * 1.2 * Math.cos(a), n.sy + r * 1.2 * Math.sin(a)); }
        ctx.closePath();
      } else ctx.arc(n.sx, n.sy, r, 0, TAU);
    }
    function drawCore(n) {
      const s = n.ss * n.scale;
      const bump = 1 + beat * .28;
      ctx.globalCompositeOperation = 'lighter';
      const size = 330 * s * bump;
      ctx.globalAlpha = (.5 + risk * .3) * (1 - n.dim * .5);
      ctx.drawImage(sprite(coreRgb), n.sx - size / 2, n.sy - size / 2, size, size);
      const inner = 112 * s * (1 + beat * .4);
      ctx.globalAlpha = .9;
      ctx.drawImage(sprite(coreRgb, true), n.sx - inner / 2, n.sy - inner / 2, inner, inner);
      ctx.globalAlpha = 1;
      ctx.globalCompositeOperation = 'source-over';

      // Gyroscope rings around the core
      const gyros = [{ r: 34, tx: t * .5, tz: .5 }, { r: 44, tx: -t * .33 + 1, tz: -.7 }, { r: 55, tx: .9, tz: t * .24 }];
      ctx.setLineDash([]);
      gyros.forEach((g, i) => {
        ctx.beginPath();
        for (let k = 0; k <= 48; k++) {
          ringPoint(g, (k / 48) * TAU, g.r * n.scale);
          project(ox, oy, oz);
          if (k === 0) ctx.moveTo(px, py); else ctx.lineTo(px, py);
        }
        ctx.lineWidth = 1;
        ctx.strokeStyle = `rgba(255,${200 - i * 30},${140 - i * 40},${.5 - i * .1})`;
        if (i === 2) ctx.setLineDash([3, 6]);
        ctx.stroke();
        ctx.setLineDash([]);
      });

      // The Sentinel mark at the heart of it
      const k = 26 * s / 349;
      ctx.save();
      ctx.translate(n.sx, n.sy);
      ctx.rotate(Math.sin(t * .3) * .08);
      ctx.scale(k, k);
      ctx.translate(-226.5, -333);
      ctx.fillStyle = '#1a0900';
      ctx.fill(markPath, 'evenodd');
      ctx.restore();
    }
    const markPath = new Path2D(MARK);

    function drawNode(n) {
      if (n.p <= 0) return;
      n.scale = outBack(clamp(n.p * 1.25, 0, 1));
      const depthFade = clamp(1 - (n.sz + 200) / 800, .42, 1);
      n.alpha = depthFade * (1 - n.dim * .78);
      if (n === core) { n.r = 26 * n.ss; drawCore(n); return; }

      const r = n.style.r * n.ss * n.scale * (1 + n.hot * .4 + n.flash * .3);
      n.r = r;
      ctx.globalCompositeOperation = 'lighter';
      // Trail while flying out of the core
      if (n.p < 1 && quality > 0) {
        const glow = sprite(n.style.rgb);
        ringPoint(n.ring, n.theta + n.ring.phase, n.ring.r);
        const tx = ox, ty = oy, tz = oz;
        for (let k = 1; k <= 7; k++) {
          const e = outExpo(clamp(n.p - k * .028, 0, 1));
          project(tx * e, ty * e, tz * e);
          const size = (26 - k * 2.5) * ps;
          ctx.globalAlpha = (1 - k / 8) * .8;
          ctx.drawImage(glow, px - size / 2, py - size / 2, size, size);
        }
      }
      const halo = (r * 6 + n.hot * r * 4) * (1 + n.flash * .7);
      ctx.globalAlpha = n.alpha * (.5 + n.hot * .45 + n.flash * .4);
      ctx.drawImage(sprite(n.style.rgb), n.sx - halo / 2, n.sy - halo / 2, halo, halo);
      ctx.globalAlpha = 1;
      ctx.globalCompositeOperation = 'source-over';

      const [cr, cg, cb] = n.style.rgb;
      ctx.globalAlpha = n.alpha;
      glyph(n, r);
      ctx.fillStyle = '#0a0502';
      ctx.fill();
      ctx.lineWidth = 1.5 + n.hot * .7;
      ctx.strokeStyle = `rgb(${cr},${cg},${cb})`;
      ctx.stroke();
      glyph(n, r * .42);
      ctx.fillStyle = `rgb(${cr},${cg},${cb})`;
      ctx.fill();

      // Selection reticle
      if (n === selected || n === hover) {
        const ret = r + 8 + Math.sin(t * 3) * 1.2;
        const spin = t * (n === selected ? 1.3 : 2.2);
        ctx.lineWidth = 1.2;
        ctx.strokeStyle = `rgba(${cr},${cg},${cb},${n === selected ? .95 : .6})`;
        for (let i = 0; i < 4; i++) {
          ctx.beginPath();
          ctx.arc(n.sx, n.sy, ret, spin + i * TAU / 4, spin + i * TAU / 4 + TAU / 7);
          ctx.stroke();
        }
      }
      ctx.globalAlpha = 1;
    }
    function drawShocks() {
      for (let i = shocks.length - 1; i >= 0; i--) {
        const s = shocks[i];
        s.t += dtNow;
        const u = s.t / s.dur;
        if (u >= 1) { shocks.splice(i, 1); continue; }
        const e = outExpo(u), R = s.R * e;
        const alpha = (1 - u) * (1 - u) * (s.alpha || .95);
        ctx.strokeStyle = `rgba(${s.rgb[0]},${s.rgb[1]},${s.rgb[2]},${alpha})`;
        ctx.lineWidth = (s.width || 2.4) * (1 - u) + .4;
        ctx.beginPath();
        if (s.node) {
          ctx.arc(s.node.sx, s.node.sy, R * s.node.ss, 0, TAU);
        } else {
          for (let k = 0; k <= 72; k++) {
            const a = (k / 72) * TAU;
            project(R * Math.cos(a), 0, R * Math.sin(a));
            if (k === 0) ctx.moveTo(px, py); else ctx.lineTo(px, py);
          }
        }
        ctx.stroke();
      }
    }

    // ---------- Frame ----------
    let dtNow = .016, last = performance.now(), visible = true, raf = 0;
    function update(dt) {
      clock += dt;
      t += dt;
      const orbit = reduce ? 0 : (selected && selected !== core) || hover ? 0 : 1;
      rings.forEach((ring) => { ring.speed = damp(ring.speed === undefined ? 1 : ring.speed, orbit, 2.5, dt); ring.phase += ring.w * ring.speed * dt; });
      if (!reduce) sweep += dt * (.34 + risk * .4);

      // Heartbeat and periodic shock from the core, faster when the risk is higher
      if (!reduce) {
        const phase = (t % period) / period;
        beat = Math.pow(Math.max(0, 1 - phase * 3.2), 2.2);
        shockTimer += dt;
        if (shockTimer > period * 1.6 && clock > endAt) {
          shockTimer = 0;
          shocks.push({ t: 0, dur: 2.4, R: 372, rgb: coreRgb, alpha: .32 + risk * .4, width: 1.6 });
        }
      }

      // Timeline
      if (clock < endAt + 1) {
        stages.forEach((s) => { if (clock >= s.t && s.i > stageNow) { stageNow = s.i; if (options.onStage) options.onStage(s.i); } });
        if (!swept && clock >= sweepAt) {
          swept = true;
          shocks.push({ t: 0, dur: 1.5, R: 430, rgb: [255, 200, 140], alpha: .9, width: 3 });
          nodes.forEach((n) => { n.flash = 1; });
        }
        if (!finished && clock >= endAt) { finished = true; if (options.onDone) options.onDone(); }
      }
      if (options.compact && clock > endAt + 11) replay();

      // Camera
      if (!reduce && !drag && !cam.lock && (!selected || selected === core) && clock - lastInput > 2.2) { cam.yaw += dt * .05; cam.yawT = cam.yaw; }
      if (cam.lock) {
        cam.yaw = damp(cam.yaw, cam.yawT, 3, dt);
        if (Math.abs(cam.yaw - cam.yawT) < .002) cam.lock = false;
      }
      cam.pitch = damp(cam.pitch, cam.pitchT, 3, dt);
      cam.zoom = damp(cam.zoom, cam.zoomT, 5, dt);
      cam.fx = damp(cam.fx, cam.fxT, 3, dt); cam.fy = damp(cam.fy, cam.fyT, 3, dt); cam.fz = damp(cam.fz, cam.fzT, 3, dt);
      if (options.onZoom) options.onZoom(cam.zoom / baseZoom);
      camSetup();

      // Nodes and highlight state
      const focus = hover || (selected && selected !== core ? selected : null);
      const linked = focus ? links.get(focus.id) : null;
      nodes.forEach((n) => {
        n.p = clamp((clock - n.t0) / 1, 0, 1);
        if (n === core) { n.x = n.y = n.z = 0; } else {
          ringPoint(n.ring, n.theta + n.ring.phase, n.ring.r);
          const e = outExpo(n.p);
          n.x = ox * e; n.y = oy * e; n.z = oz * e;
        }
        project(n.x, n.y, n.z);
        n.sx = px; n.sy = py; n.ss = ps; n.sz = pz;
        const isHot = n === hover || n === selected;
        n.hot = damp(n.hot, isHot ? 1 : linked && linked.has(n.id) ? .55 : 0, 9, dt);
        n.dim = damp(n.dim, focus && n !== focus && !linked.has(n.id) && n !== core ? (hover && !selected ? .55 : 1) : 0, 6, dt);
        n.flash = damp(n.flash, 0, 2.6, dt);
      });
      edges.forEach((e) => {
        const isHot = focus && (e.a === focus || e.b === focus);
        e.hot = damp(e.hot, isHot ? 1 : 0, 8, dt);
        e.dim = damp(e.dim, focus && !isHot ? 1 : 0, 6, dt);
      });
    }
    function render() {
      drawBackground();
      drawDust();
      if (!options.compact || quality > 1) drawFloor();
      drawSweep();
      drawOrbits();
      drawEdges();
      nodes.slice().sort((a, b) => b.sz - a.sz).forEach(drawNode);
      drawShocks();
      if (labelHost) {
        if (declutterTick++ % 8 === 0 && clock > .4) declutter();
        nodes.forEach((n) => {
          const on = n.labelOn;
          n.el.style.transform = `translate3d(${(n.sx).toFixed(1)}px,${(n.sy + n.r + 6).toFixed(1)}px,0) translateX(-50%)`;
          n.el.style.opacity = on ? Math.max(n.alpha, n === hover || n === selected ? 1 : 0).toFixed(2) : 0;
          n.el.style.pointerEvents = on ? 'auto' : 'none';
          n.el.classList.toggle('is-hot', n === hover || n === selected);
        });
      }
    }
    function frame(now) {
      raf = requestAnimationFrame(frame);
      if (!visible || document.hidden) { last = now; return; }
      const rawDt = (now - last) / 1000;
      dtNow = Math.min(rawDt, .1);
      last = now;
      update(dtNow);
      ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
      render();

      // Drop detail on slow machines rather than stutter.
      if (clock > 3 && rawDt < 1) {
        slow = lerp(slow, rawDt > .04 ? 1 : 0, .02);
        if (slow > .7 && quality > 0 && ++frames > 90) { quality--; frames = 0; slow = 0; resize(); }
      }
    }

    new IntersectionObserver((en) => { visible = en[0].isIntersecting; }).observe(host);
    new ResizeObserver(resize).observe(host);
    resize();
    replay();
    camSetup();
    raf = requestAnimationFrame(frame);

    const api = {
      select, zoomBy, fit,
      // Clear any selection first, or the replay plays with most of the scene dimmed.
      replay() { if (selected !== core && !options.compact) { cam.lock = false; cam.pitchT = .46; select(core.id); } setHover(null); replay(); },
      neighbours: (id) => [...(links.get(id) || [])].map((k) => byId[k]),
      nodes,
      get selected() { return selected; },
      get finished() { return finished; },
      stop() { cancelAnimationFrame(raf); },
    };
    return api;
  }

  return { create };
})();
