/* SentinelTI — living evidence tiles. They play the role video plays on a showreel page:
   each one is a small piece of real analysis, animated with CSS only so dozens stay cheap.
   All values are illustrative example data. */
window.SentinelTiles = (function () {
  const rng = (seed) => () => (seed = (seed * 16807) % 2147483647) / 2147483647;

  function hexLines(seed, count) {
    const r = rng(seed);
    const byte = () => Math.floor(r() * 256).toString(16).padStart(2, '0').toUpperCase();
    const lines = [];
    for (let i = 0; i < count; i++) {
      const cells = Array.from({ length: 8 }, () => (r() > .72 ? `<b>${byte()}</b>` : byte())).join(' ');
      lines.push(`<i>${(i * 16).toString(16).padStart(6, '0')}</i> ${cells}`);
    }
    return lines;
  }
  const SECTIONS = [['.text', 6.1], ['.rdata', 4.2], ['UPX0', .1], ['UPX1', 7.9], ['.rsrc', 3.4], ['.reloc', 2.1]];
  const STRINGS = [
    'kernel32.dll', 'http://185.244.25[.]14/gate.php', 'VirtualAllocEx', 'Software\\Microsoft\\Windows\\Run',
    'WriteProcessMemory', 'cmd.exe /c', '91.92.109[.]3', 'CreateRemoteThread', 'Mozilla/4.0 (compatible)',
    'RegSetValueExW', 'powershell -enc', 'InternetOpenA', 'URLDownloadToFileA', 'GetProcAddress',
  ];

  const kinds = {
    hex(o) {
      const lines = hexLines(o.seed || 77, 18);
      lines[0] = '<i>000000</i> <b class="hit">4D 5A</b> 90 00 03 00 00 00';
      const body = lines.map((l) => `<div>${l}</div>`).join('');
      return `<div class="t-scroll t-mono"><div class="t-scroll__in">${body}${body}</div></div>`;
    },
    fingerprint() {
      const lines = hexLines(31, 9).map((l) => `<div>${l}</div>`).join('');
      return `<div class="t-fp"><div class="t-mono t-fp__hex"><div><i>000000</i> <b class="hit">4D 5A</b> 90 00 03 00 00 00</div>${lines}</div>
        <div class="t-fp__side">
          <span class="t-tag t-tag--hot">Disguised</span>
          <p>Named <b>invoice_0923.pdf</b>, but the magic bytes say <b>Windows PE</b>.</p>
          <div class="t-kv"><span>SHA-256</span><code>e3b0c442…1a7c2d9e</code><span>Entropy</span><code>7.82</code><span>Size</span><code>412 KB</code></div>
        </div></div>`;
    },
    entropy() {
      return `<div class="t-bars">${SECTIONS.map(([n, v], i) => `<div class="t-bar${v > 7.2 ? ' is-hot' : ''}"><span>${n}</span><i><b style="--w:${(v / 8) * 100}%;--d:${i * .18}s"></b></i><em>${v.toFixed(1)}</em></div>`).join('')}</div>`;
    },
    chain() {
      const apis = ['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread'];
      return `<div class="t-chain">${apis.map((a, i) => `<div class="t-chain__step" style="--d:${i * .7}s"><i></i><code>${a}</code></div>`).join('')}
        <div class="t-chain__out"><span class="t-tag t-tag--hot">Proven</span><code>T1055</code> Process Injection</div></div>`;
    },
    radar() {
      const blips = [[28, 34, 0], [66, 26, .9], [72, 62, 1.8], [38, 70, 2.5], [54, 44, 3.2]];
      return `<div class="t-radar"><div class="t-radar__dial"><i class="t-radar__sweep"></i>${blips.map(([x, y, d]) => `<b style="left:${x}%;top:${y}%;--d:${d}s"></b>`).join('')}</div></div>`;
    },
    attck(o) {
      const lit = { 3: 'T1055', 9: 'T1547', 14: 'T1071', 20: 'T1027', 26: 'T1105' };
      const r = rng(o.seed || 5);
      const cells = Array.from({ length: 32 }, (_, i) => (lit[i]
        ? `<span class="is-lit" style="--d:${(i % 5) * .5}s">${lit[i]}</span>`
        : `<span style="opacity:${(.25 + r() * .5).toFixed(2)}"></span>`)).join('');
      return `<div class="t-attck">${cells}</div>`;
    },
    yara() {
      return `<div class="t-yara t-mono"><i class="t-yara__scan"></i>
<div><b>rule</b> Injection_API_Chain {</div><div>&nbsp; <em>meta:</em> score = 10</div><div>&nbsp; <em>strings:</em></div><div>&nbsp;&nbsp; $a = "VirtualAllocEx"</div><div>&nbsp;&nbsp; $b = "WriteProcessMemory"</div><div>&nbsp;&nbsp; $c = "CreateRemoteThread"</div><div>&nbsp; <em>condition:</em> all of them</div><div>}</div><span class="t-tag t-tag--hot t-yara__hit">Match</span></div>`;
    },
    strings() {
      const items = STRINGS.map((s) => `<div class="${/\[\.\]|enc|Run/.test(s) ? 'hit' : ''}">${s.replace(/</g, '&lt;')}</div>`).join('');
      return `<div class="t-scroll t-mono t-scroll--slow"><div class="t-scroll__in">${items}${items}</div></div>`;
    },
    gauge(o) {
      const value = o.value === undefined ? 94 : o.value;
      const label = o.label || 'Critical';
      return `<div class="t-gauge" style="--v:${value}"><svg viewBox="0 0 100 100" aria-hidden="true"><circle cx="50" cy="50" r="42"/><circle class="t-gauge__arc" cx="50" cy="50" r="42" pathLength="100"/></svg><div><strong>${value}</strong><span>${label}</span></div></div>`;
    },
    hash() {
      const r = rng(19);
      const row = () => Array.from({ length: 12 }, () => '0123456789abcdef'[Math.floor(r() * 16)]).join('');
      return `<div class="t-hash t-mono"><span>SHA-256</span>${[0, 1, 2, 3].map((i) => `<div style="--d:${i * .35}s">${row()}${row()}</div>`).join('')}</div>`;
    },
    fact() {
      const facts = ['SHA-256 matches quarantine', 'API VirtualAllocEx in file', 'Run-key string in file', 'YARA rule hit again', 'Section UPX1 confirmed', 'Technique has proof'];
      return `<div class="t-facts"><strong>33 <span>of 33 facts verified</span></strong>${facts.map((f, i) => `<div style="--d:${i * .45}s"><i></i>${f}</div>`).join('')}</div>`;
    },
    pdf() {
      return `<div class="t-pdf"><div class="t-pdf__page"><b>invoice_0923.exe</b><span class="t-tag t-tag--hot">Critical · 94</span><p></p><p></p><p style="width:62%"></p><h6></h6><p></p><p style="width:80%"></p><h6></h6><div class="t-pdf__rows"><i></i><i></i><i></i><i></i></div></div></div>`;
    },
    rep() {
      const rows = [['VirusTotal', '65 engines', 90], ['AlienVault OTX', '50 pulses', 74], ['Internal notes', '3 matched', 42]];
      return `<div class="t-bars t-bars--rep">${rows.map(([n, v, w], i) => `<div class="t-bar is-hot"><span>${n}</span><i><b style="--w:${w}%;--d:${i * .25}s"></b></i><em>${v}</em></div>`).join('')}</div>`;
    },
    imports() {
      const rows = ['kernel32.dll', 'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread', 'advapi32.dll', 'RegSetValueExW', 'wininet.dll', 'HttpSendRequestA'];
      return `<div class="t-imports t-mono">${rows.map((r, i) => (r.endsWith('.dll') ? `<em>${r}</em>` : `<div style="--d:${i * .4}s">${r}</div>`)).join('')}</div>`;
    },
    drop() {
      return `<div class="t-drop"><div class="t-drop__zone"></div><div class="t-drop__file"><span>.pdf</span></div></div>`;
    },
    graph() {
      const pts = [[50, 50, 7], [18, 26, 3], [82, 22, 4], [88, 66, 3], [60, 88, 3], [20, 74, 4], [40, 14, 3]];
      const lines = pts.slice(1).map(([x, y], i) => `<line x1="50" y1="50" x2="${x}" y2="${y}" style="--d:${i * .4}s"/>`).join('');
      const dots = pts.map(([x, y, r], i) => `<circle class="${i === 0 ? 'is-core' : ''}" cx="${x}" cy="${y}" r="${r}" style="--d:${i * .3}s"/>`).join('');
      return `<svg class="t-graph" viewBox="0 0 100 100" preserveAspectRatio="xMidYMid meet" aria-hidden="true">${lines}${dots}</svg>`;
    },
  };

  function render(kind, options) {
    return `<div class="tile tile--${kind}"><div class="tile__in">${kinds[kind](options || {})}</div></div>`;
  }
  return { render };
})();
