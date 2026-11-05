/* SentinelTI — thin client for the backend API. The session lives in an HttpOnly cookie. */
window.SentinelAPI = (function () {
  class ApiError extends Error {
    constructor(status, message) { super(message); this.status = status; }
  }

  async function request(path, options = {}) {
    let res;
    try {
      res = await fetch('/api' + path, { credentials: 'same-origin', ...options });
    } catch (e) {
      throw new ApiError(0, 'Can’t reach the server');
    }
    if (res.status === 204) return null;
    const isJson = (res.headers.get('content-type') || '').includes('application/json');
    const body = isJson ? await res.json().catch(() => null) : null;
    if (!res.ok) {
      const detail = body && typeof body.detail === 'string' ? body.detail : 'Something went wrong (' + res.status + ')';
      throw new ApiError(res.status, detail);
    }
    return body;
  }
  const json = (method, path, data) => request(path, {
    method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data),
  });

  return {
    ApiError,
    me: () => request('/auth/me'),
    login: (email, password) => json('POST', '/auth/login', { email, password }),
    logout: () => request('/auth/logout', { method: 'POST' }),
    list: (limit = 25) => request('/analyses?limit=' + limit),
    get: (id) => request('/analyses/' + encodeURIComponent(id)),
    graph: (id) => request('/analyses/' + encodeURIComponent(id) + '/graph'),
    chat: (id, message) => json('POST', '/analyses/' + encodeURIComponent(id) + '/chat', { message }),
    lookup: (sha256) => json('POST', '/analyses/lookup', { sha256 }),
    upload(file) {
      const form = new FormData();
      form.append('file', file, file.name);
      return request('/analyses', { method: 'POST', body: form });
    },
    eventsUrl: (id) => '/api/analyses/' + encodeURIComponent(id) + '/events',
    reportUrl: (id) => '/api/analyses/' + encodeURIComponent(id) + '/report.pdf',
    loginUrl: (next) => 'login.html?next=' + encodeURIComponent(next || location.pathname.split('/').pop() + location.search),
  };
})();
