/* SentinelTI — How it Works: fills the agent list and plays the hero entrance. */
(function () {
  const S = window.Sentinel;
  const { agents } = window.SentinelData;
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  document.getElementById('agent-list').innerHTML = agents.map((a) => `
    <li class="agent">
      <span class="agent__n">${esc(a.n)}</span>
      <div>
        <h3 class="agent__name">${esc(a.name)}</h3>
        <p>${esc(a.aim)}</p>
        <div class="agent__tools">${a.tools.map((t) => `<span class="chip">${esc(t)}</span>`).join('')}</div>
      </div>
    </li>`).join('');

  if (window.gsap && !S.reduce) {
    gsap.from('.story-hero h1 .line-mask > span', { yPercent: 110, duration: 1.3, ease: 'expo.out', stagger: .1 });
    gsap.from('.story-hero p', { y: 24, opacity: 0, filter: 'blur(12px)', duration: 1.2, ease: 'expo.out', delay: .4, clearProps: 'filter' });
    if (window.ScrollTrigger) {
      document.querySelectorAll('.arch, .arch__grid, .flow').forEach((box) => {
        gsap.from(box.children, { opacity: 0, y: 14, duration: .8, ease: 'expo.out', stagger: .06, scrollTrigger: { trigger: box, start: 'top 88%', once: true } });
      });
    }
  }
  if (location.hash === '#agents') {
    const target = document.getElementById('agents');
    requestAnimationFrame(() => { if (S.lenis) S.lenis.scrollTo(target, { immediate: true, offset: -90 }); else target.scrollIntoView(); });
  }
})();
