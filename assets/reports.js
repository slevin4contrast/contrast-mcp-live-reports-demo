// Shared behaviour for every live report page.
//
// This used to be copy-pasted into all eight pages, so a one-line fix meant
// eight regex edits and the copies had already drifted apart. Each page now
// supplies only what is genuinely its own: which endpoint to call and how to
// draw the result.

(function (global) {
  'use strict';

  var ESCAPES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };

  function esc(v) {
    return String(v == null ? '' : v).replace(/[&<>"']/g, function (c) { return ESCAPES[c]; });
  }

  // These demo apps all carry the same prefix, which crowds out the part that matters.
  function shortApp(name) {
    return String(name == null ? '' : name).replace(/^SAML-cargocats-/, '');
  }

  // Served from GitHub Pages there is no local server to call.
  var HOSTED = ['localhost', '127.0.0.1', ''].indexOf(global.location.hostname) === -1;

  function snapshotHref() {
    return global.location.pathname.split('/').pop().replace(/\.html$/, '_static.html');
  }

  function badge(text, kind) {
    var el = document.getElementById('sourceBadge');
    if (!el) return;
    el.textContent = text;
    el.className = 'source-badge ' + (kind || 'mock');
  }

  function banner(html, colour) {
    var el = document.getElementById('errorBanner');
    if (!el) return;
    el.style.display = 'block';
    el.style.background = colour === 'info' ? 'rgba(102, 126, 234, 0.15)' : 'rgba(255, 68, 68, 0.15)';
    el.style.borderColor = colour === 'info' ? '#667eea' : '#ff4444';
    el.innerHTML = html;
  }

  function clearBanner() {
    var el = document.getElementById('errorBanner');
    if (el) el.style.display = 'none';
  }

  function hostedNotice() {
    badge('SNAPSHOT', 'mock');
    banner('<strong>Hosted copy, so no live data.</strong> This page is served from GitHub Pages, '
      + 'which cannot reach a Contrast organization. Clone the repo and run <code>npm start</code> '
      + 'to see it live, or open the <a href="' + snapshotHref()
      + '" style="color:#8fa2ff; font-weight:bold;">static snapshot</a>.', 'info');
  }

  // Say what actually broke. An expired session is not the same problem as a
  // server that is not running, and telling someone to start a server that is
  // plainly already answering wastes their time.
  function failureBanner(err) {
    var msg = String((err && err.message) || err || '');
    var link = ' Or open the <a href="' + snapshotHref() + '" style="color:#8fa2ff;">static snapshot</a>.';
    badge('NO DATA', 'mock');

    if (/token expired|reauthorize|sign in/i.test(msg)) {
      banner('<strong>Contrast session expired.</strong> The server is running fine, it just has no '
        + 'valid token. If it signed in with <code>npm run login</code> it renews itself, so this '
        + 'usually means that session was revoked. Otherwise run a Contrast command in Claude Code, '
        + 'then press Refresh.' + link);
    } else if (msg === 'NOT_REPORT_SERVER') {
      banner('<strong>Something else is on port 3000.</strong> This page loaded, but the API returned '
        + 'a web page instead of data, so the process answering is not the report server. Stop it, '
        + 'then run <code>npm start</code> from the repo.' + link);
    } else if (/failed to fetch|networkerror|load failed/i.test(msg)) {
      banner('<strong>Cannot reach the local server.</strong> Start it with <code>npm start</code> and '
        + 'open this page at <code>http://localhost:3000</code>.' + link);
    } else {
      banner('<strong>Could not load live data.</strong> ' + esc(msg) + link);
    }
  }

  // One fetch path for every page, so source labelling and error handling cannot drift.
  function fetchData(endpoint) {
    return global.fetch(endpoint, { cache: 'no-store' }).then(function (res) {
      var ct = res.headers.get('content-type') || '';
      if (ct.indexOf('json') === -1) throw new Error('NOT_REPORT_SERVER');
      return res.json().then(function (d) {
        if (!res.ok) throw new Error(d.error || res.statusText);
        return d;
      });
    });
  }

  function markLoaded(d) {
    badge(d.source === 'live' ? 'LIVE' : 'MOCK DATA', d.source === 'live' ? 'live' : 'mock');
    var el = document.getElementById('updated');
    if (el) el.textContent = 'Last refreshed ' + new Date(d.generatedAt).toLocaleTimeString();
  }

  // The loop every page runs: skip the call when hosted, fetch, render, and turn
  // any failure into an explanation rather than a page stuck on "Loading".
  function createLoader(endpoint, render) {
    return function load(query) {
      clearBanner();
      if (HOSTED) { hostedNotice(); return Promise.resolve(); }
      var url = typeof endpoint === 'function' ? endpoint(query) : endpoint;
      return fetchData(url).then(function (d) {
        markLoaded(d);
        render(d);
      }).catch(failureBanner);
    };
  }

  function onRefresh(handler) {
    var btn = document.getElementById('refreshBtn');
    if (btn) btn.addEventListener('click', function () { handler(); });
  }

  global.Reports = {
    esc: esc,
    shortApp: shortApp,
    HOSTED: HOSTED,
    badge: badge,
    banner: banner,
    clearBanner: clearBanner,
    hostedNotice: hostedNotice,
    failureBanner: failureBanner,
    fetchData: fetchData,
    markLoaded: markLoaded,
    createLoader: createLoader,
    onRefresh: onRefresh,
  };
}(window));
