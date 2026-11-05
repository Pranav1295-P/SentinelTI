/* SentinelTI — atmospheric vortex field (raw WebGL, no deps).
   A twisted, domain-warped fbm read through polar coordinates; the twist
   shears the noise into slow spiral streaks around a bright elliptical eye. */
(function () {
  const VERT = `attribute vec2 p; void main(){ gl_Position = vec4(p,0.,1.); }`;
  const FRAG = `
precision highp float;
uniform vec2 uRes; uniform float uTime; uniform vec2 uMouse; uniform float uLight; uniform float uIntro;
float h(vec2 p){ p = fract(p*vec2(123.34,456.21)); p += dot(p,p+45.32); return fract(p.x*p.y); }
float vn(vec2 p){ vec2 i=floor(p), f=fract(p); f=f*f*(3.-2.*f);
  return mix(mix(h(i),h(i+vec2(1,0)),f.x), mix(h(i+vec2(0,1)),h(i+vec2(1,1)),f.x), f.y); }
float fbm(vec2 p){ float v=0., a=.5; mat2 m=mat2(1.6,1.2,-1.2,1.6);
  for(int i=0;i<5;i++){ v+=a*vn(p); p=m*p; a*=.5; } return v; }
void main(){
  vec2 uv = (gl_FragCoord.xy - .5*uRes) / min(uRes.x, uRes.y);
  uv -= uMouse * .04;
  vec2 q = uv; q.y *= 1.55; q.x *= .82;
  float r = length(q);
  float a = atan(q.y, q.x);
  float t = uTime;
  float tw = a + 1.9/(r + .32) - t*.06 + (1.-uIntro)*2.5;
  vec2 sp = vec2(cos(tw), sin(tw)) * (r*1.7 + .2);
  vec2 w = vec2(fbm(sp*1.4 + t*.04), fbm(sp*1.4 - t*.035 + 7.3));
  float n = fbm(sp*2.2 + w*1.6);
  float fine = fbm(sp*6. + w*3. - t*.02);
  float ring = exp(-pow((r - .40)/.30, 2.));
  float eye = smoothstep(.0, .30, r);
  float body = clamp(n*1.6 - .42 + ring*.95, 0., 1.);
  body = mix(body, body*eye + (1.-eye)*.62, .55);
  float streak = smoothstep(.38, .9, n*.75 + fine*.5) * ring;

  vec3 deep   = mix(vec3(.051,.020,.169), vec3(.86,.85,.92), uLight);
  vec3 indigo = mix(vec3(.13,.07,.36),  vec3(.72,.69,.88), uLight);
  vec3 violet = mix(vec3(.40,.28,.86),  vec3(.55,.45,.95), uLight);
  vec3 lilac  = mix(vec3(.78,.76,.90),  vec3(.97,.96,1.),  uLight);
  vec3 glow   = vec3(1.,.99,1.);

  vec3 col = deep;
  col = mix(col, indigo, smoothstep(.05,.55, body));
  col = mix(col, violet, smoothstep(.45,.85, body)*.55);
  col = mix(col, lilac,  smoothstep(.62,.98, body));
  col = mix(col, glow,   streak*.7);
  // warm signal bloom low-right, like light leaking past the eye
  float leak = smoothstep(1.2, .1, length(uv - vec2(.75,-.45)));
  col += vec3(.35,.08,.18) * leak * .35 * (1.-uLight);
  float vig = smoothstep(1.35, .35, length(uv*vec2(.8,1.)));
  col *= mix(.55, 1., vig);
  col = mix(deep, col, uIntro);
  gl_FragColor = vec4(col, 1.);
}`;

  function make(canvas, opts) {
    const gl = canvas.getContext('webgl', { antialias: false, premultipliedAlpha: false, powerPreference: 'low-power' });
    if (!gl) { canvas.style.background = 'radial-gradient(ellipse at center, #c8c6d6 0%, #3b2a8a 35%, #0d052b 75%)'; return null; }
    const sh = (type, src) => { const s = gl.createShader(type); gl.shaderSource(s, src); gl.compileShader(s); if (!gl.getShaderParameter(s, gl.COMPILE_STATUS)) console.error(gl.getShaderInfoLog(s)); return s; };
    const prog = gl.createProgram();
    gl.attachShader(prog, sh(gl.VERTEX_SHADER, VERT));
    gl.attachShader(prog, sh(gl.FRAGMENT_SHADER, FRAG));
    gl.linkProgram(prog);
    gl.useProgram(prog);
    const buf = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, buf);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW);
    const loc = gl.getAttribLocation(prog, 'p');
    gl.enableVertexAttribArray(loc);
    gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);
    const U = (n) => gl.getUniformLocation(prog, n);
    const uRes = U('uRes'), uTime = U('uTime'), uMouse = U('uMouse'), uLight = U('uLight'), uIntro = U('uIntro');

    const scale = (opts && opts.scale) || .65; // render under-res like the reference, CSS upsamples
    function resize() {
      const r = canvas.getBoundingClientRect();
      const dpr = Math.min(window.devicePixelRatio || 1, 1.5);
      canvas.width = Math.max(2, Math.round(r.width * dpr * scale));
      canvas.height = Math.max(2, Math.round(r.height * dpr * scale));
      gl.viewport(0, 0, canvas.width, canvas.height);
    }
    resize();
    addEventListener('resize', resize);

    const mouse = { x: 0, y: 0, tx: 0, ty: 0 };
    addEventListener('pointermove', (e) => { mouse.tx = (e.clientX / innerWidth - .5) * 2; mouse.ty = -(e.clientY / innerHeight - .5) * 2; });

    let light = document.documentElement.dataset.theme === 'light' ? 1 : 0, lightT = light;
    addEventListener('themechange', (e) => { lightT = e.detail.light ? 1 : 0; });

    const state = { intro: 0, introT: 0, running: true };
    let t0 = performance.now(), last = t0, visible = true;
    new IntersectionObserver((en) => { visible = en[0].isIntersecting; }).observe(canvas);
    // frame-rate independent easing toward a target
    const ease = (k, f) => 1 - Math.pow(1 - k, f);

    function frame(now) {
      requestAnimationFrame(frame);
      const f = Math.min(now - last, 200) / 16.67;
      last = now;
      if (!visible || document.hidden) return;
      const t = (now - t0) / 1000;
      mouse.x += (mouse.tx - mouse.x) * ease(.04, f); mouse.y += (mouse.ty - mouse.y) * ease(.04, f);
      light += (lightT - light) * ease(.06, f);
      state.intro += (state.introT - state.intro) * ease(.025, f);
      gl.uniform2f(uRes, canvas.width, canvas.height);
      gl.uniform1f(uTime, t);
      gl.uniform2f(uMouse, mouse.x, mouse.y);
      gl.uniform1f(uLight, light);
      gl.uniform1f(uIntro, state.intro);
      gl.drawArrays(gl.TRIANGLES, 0, 3);
    }
    requestAnimationFrame(frame);
    return { show() { state.introT = 1; }, state };
  }

  window.SentinelVortex = { make };
})();
