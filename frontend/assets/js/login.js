/* SentinelTI — sign in. */
(function () {
  const S = window.Sentinel;
  const API = window.SentinelAPI;
  const v = window.SentinelVortex.make(document.querySelector('.auth canvas'), { scale: .5 });
  const form = document.getElementById('login');
  const submit = form.querySelector('button[type="submit"]');

  // Only ever redirect to one of our own pages.
  const next = new URLSearchParams(location.search).get('next') || '';
  const target = /^[a-z]+\.html(\?id=[0-9a-f-]{36})?$/.test(next) ? next : 'analyse.html';

  S.ready.then(() => {
    v && v.show();
    if (window.gsap && !S.reduce) gsap.from(form, { y: 40, opacity: 0, duration: 1.1, ease: 'expo.out', delay: .1 });
  });

  API.me().then(() => { location.replace(target); }).catch(() => {});

  const shake = () => { if (window.gsap) gsap.fromTo(form, { x: -8 }, { x: 0, duration: .5, ease: 'elastic.out(1, .3)' }); };
  const setError = (id, msg) => {
    const f = document.getElementById(id).closest('.field');
    f.classList.toggle('is-bad', !!msg);
    f.querySelector('.field__err').textContent = msg || '';
  };

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const email = document.getElementById('email').value.trim();
    const password = document.getElementById('password').value;
    const badEmail = !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
    const badPassword = password.length < 8;
    setError('email', badEmail ? 'Enter a valid email' : '');
    setError('password', badPassword ? 'At least 8 characters' : '');
    if (badEmail || badPassword) { shake(); return; }

    submit.disabled = true;
    try {
      await API.login(email, password);
      location.href = target;
    } catch (err) {
      submit.disabled = false;
      setError('password', err.message);
      shake();
    }
  });
})();
