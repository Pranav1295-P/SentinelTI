/* SentinelTI — ambient ember field (raw WebGL, no dependencies).
   Slow domain-warped noise, rendered small and scaled up so it reads as a soft blur.
   Each section sets where the glow sits and how strong it is. */
(function () {
  const VERT = 'attribute vec2 p; void main(){ gl_Position = vec4(p,0.,1.); }';
  const FRAG = `
precision mediump float;
uniform vec2 uRes; uniform float uTime; uniform vec2 uCenter; uniform float uPower; uniform float uHeat; uniform float uIntro;
float h(vec2 p){ p = fract(p*vec2(123.34,456.21)); p += dot(p,p+45.32); return fract(p.x*p.y); }
float vn(vec2 p){ vec2 i=floor(p), f=fract(p); f=f*f*(3.-2.*f);
  return mix(mix(h(i),h(i+vec2(1,0)),f.x), mix(h(i+vec2(0,1)),h(i+vec2(1,1)),f.x), f.y); }
float fbm(vec2 p){ float v=0., a=.5; mat2 m=mat2(1.6,1.2,-1.2,1.6);
  for(int i=0;i<4;i++){ v+=a*vn(p); p=m*p; a*=.5; } return v; }
void main(){
  vec2 uv = gl_FragCoord.xy/uRes;
  float ar = uRes.x/uRes.y;
  vec2 p = (uv-.5)*vec2(ar,1.);
  vec2 c = (vec2(uCenter.x,1.-uCenter.y)-.5)*vec2(ar,1.);
  float t = uTime*.035;
  vec2 q = p*1.5;
  float warp = fbm(q*1.2 - t*1.4);
  float n = fbm(q + vec2(t,-t*.6) + warp*.9);
  float d = length((p-c)*vec2(.72,1.));
  float glow = exp(-d*d*1.7)*(.42 + n*1.2);
  float streak = smoothstep(.42,.86, fbm(q*2.2 + n*1.6 + t*2.));
  float v = glow*uPower*(.72 + .42*streak)*uIntro;
  vec3 col = mix(vec3(.26,.045,0.), vec3(1.,.36,.02), clamp(v*1.7,0.,1.));
  col = mix(col, vec3(1.,.70,.32), smoothstep(.62,1.15,v)*uHeat);
  col *= clamp(v*1.5,0.,1.);
  col += (h(gl_FragCoord.xy + uTime) - .5)*.012; // dither away banding on black
  gl_FragColor = vec4(col,1.);
}`;

  function make(canvas) {
    const gl = canvas.getContext('webgl', { antialias: false, alpha: false, powerPreference: 'low-power' });
    if (!gl) return null; // The CSS gradient on .ambient stays as the fallback.
    const compile = (type, src) => { const s = gl.createShader(type); gl.shaderSource(s, src); gl.compileShader(s); return s; };
    const prog = gl.createProgram();
    gl.attachShader(prog, compile(gl.VERTEX_SHADER, VERT));
    gl.attachShader(prog, compile(gl.FRAGMENT_SHADER, FRAG));
    gl.linkProgram(prog);
    if (!gl.getProgramParameter(prog, gl.LINK_STATUS)) return null;
    gl.useProgram(prog);
    gl.bindBuffer(gl.ARRAY_BUFFER, gl.createBuffer());
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW);
    const loc = gl.getAttribLocation(prog, 'p');
    gl.enableVertexAttribArray(loc);
    gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);
    const U = (n) => gl.getUniformLocation(prog, n);
    const u = { res: U('uRes'), time: U('uTime'), center: U('uCenter'), power: U('uPower'), heat: U('uHeat'), intro: U('uIntro') };

    const SCALE = .3;
    function resize() {
      canvas.width = Math.max(2, Math.round(innerWidth * SCALE));
      canvas.height = Math.max(2, Math.round(innerHeight * SCALE));
      gl.viewport(0, 0, canvas.width, canvas.height);
    }
    resize();
    addEventListener('resize', resize);

    const cur = { x: .5, y: .35, power: .7, heat: .4, intro: 0 };
    const to = { ...cur, intro: 0 };
    const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;
    const t0 = performance.now();
    let last = t0, drawn = 0;
    const FRAME_MS = 33; // 30fps is plenty for something this slow

    function draw(now) {
      gl.uniform2f(u.res, canvas.width, canvas.height);
      gl.uniform1f(u.time, (now - t0) / 1000);
      gl.uniform2f(u.center, cur.x, cur.y);
      gl.uniform1f(u.power, cur.power);
      gl.uniform1f(u.heat, cur.heat);
      gl.uniform1f(u.intro, cur.intro);
      gl.drawArrays(gl.TRIANGLES, 0, 3);
    }
    function frame(now) {
      requestAnimationFrame(frame);
      if (document.hidden || now - drawn < FRAME_MS) return;
      const dt = Math.min(now - last, 200) / 1000;
      last = now; drawn = now;
      const k = 1 - Math.exp(-dt * 1.4);
      for (const key in cur) cur[key] += (to[key] - cur[key]) * k;
      draw(now);
    }
    if (reduce) {
      to.intro = cur.intro = 1;
      addEventListener('resize', () => draw(t0 + 40000));
      draw(t0 + 40000);
    } else requestAnimationFrame(frame);

    return {
      show() { to.intro = 1; },
      tone(x, y, power, heat) {
        to.x = x; to.y = y; to.power = power; to.heat = heat;
        if (reduce) { Object.assign(cur, to); draw(t0 + 40000); }
      },
    };
  }

  window.SentinelAmbient = { make };
})();
