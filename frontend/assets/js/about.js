/* SentinelTI — How it Works: hero rise, card-to-full-bleed scrub, agent list. */
(function () {
  const S = window.Sentinel;
  const { agents } = window.SentinelData;

  const v = window.SentinelVortex.make(document.querySelector('.story-media__canvas'), { scale: .55 });

  document.getElementById('agent-list').innerHTML = agents.map((a) => `
    <li class="agent" style="grid-template-columns:40px 1fr;gap:12px;padding:20px 0">
      <span class="agent__n" style="grid-column:auto">${a.n}</span>
      <div style="display:grid;gap:10px">
        <h3 class="agent__name" style="grid-column:auto;font-size:var(--fs-title)">${a.name}</h3>
        <p style="margin:0;color:color-mix(in srgb,var(--on-surface) 78%,transparent)">${a.aim}</p>
        <div class="agent__tools">${a.tools.map((t) => `<span class="chip">${t}</span>`).join('')}</div>
      </div>
    </li>`).join('');

  const lines = document.querySelectorAll('[data-hero-line]');
  const sub = document.querySelector('[data-hero-sub]');
  const card = document.querySelector('.story-media__card');
  if (window.gsap && !S.reduce) {
    gsap.set(lines, { yPercent: 110 });
    gsap.set([sub, card], { opacity: 0, y: 30 });
  }

  S.ready.then(() => {
    v && v.show();
    if (!window.gsap || S.reduce) return;
    gsap.timeline({ defaults: { ease: 'expo.out' } })
      .to(lines, { yPercent: 0, duration: 1.1, stagger: .1 }, .1)
      .to(sub, { opacity: 1, y: 0, duration: 1 }, .45)
      .to(card, { opacity: 1, y: 0, duration: 1.2 }, .55);

    // The card opens to full bleed as the frame pins (reference: About hero image)
    const mm = gsap.matchMedia();
    mm.add('(min-width: 761px)', () => {
      gsap.fromTo(card, { width: '44vw', borderRadius: 20 }, {
        width: '100vw', height: '100svh', borderRadius: 0, ease: 'none',
        scrollTrigger: { trigger: '.story-media', start: 'top 70%', end: 'bottom bottom', scrub: true },
      });
    });
    mm.add('(max-width: 760px)', () => {
      gsap.fromTo(card, { width: '86vw', borderRadius: 16 }, {
        width: '100vw', borderRadius: 0, ease: 'none',
        scrollTrigger: { trigger: '.story-media', start: 'top 70%', end: 'bottom bottom', scrub: true },
      });
    });

    // Statement background breathes from violet to a deeper ink as it passes
    gsap.fromTo('.statement', { backgroundColor: '#2a1670' }, {
      backgroundColor: '#5b2a8f', ease: 'none',
      scrollTrigger: { trigger: '.statement', start: 'top bottom', end: 'bottom top', scrub: true },
    });

    document.querySelectorAll('.arch, .arch__grid, .flow').forEach((box) => {
      gsap.from(box.children, {
        opacity: 0, y: 14, duration: .8, ease: 'expo.out', stagger: .06,
        scrollTrigger: { trigger: box, start: 'top 88%', once: true },
      });
    });
  });
})();
