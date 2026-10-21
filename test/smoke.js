#!/usr/bin/env node
// Zero-dependency smoke suite. Runs the server in MOCK mode so it is
// deterministic and needs no Contrast session, which makes it safe to run
// anywhere, including CI.
//
//   npm test              everything
//   npm test -- --no-ui   skip the browser checks

const { spawn, execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const PORT = Number(process.env.TEST_PORT || 3999);
const BASE = `http://127.0.0.1:${PORT}`;
const SKIP_UI = process.argv.includes('--no-ui');

const LIVE_PAGES = ['vulnerability_dashboard', 'route_coverage', 'library_security', 'cve_impact',
                    'attack_map', 'compliance_mttr', 'poc_generator', 'smartfix_guide'];

let passed = 0;
const failures = [];

function check(name, fn) {
  try {
    const problem = fn();
    if (problem) { failures.push(`${name}: ${problem}`); process.stdout.write('x'); }
    else { passed++; process.stdout.write('.'); }
  } catch (err) {
    failures.push(`${name}: threw ${err.message}`);
    process.stdout.write('x');
  }
}

async function checkAsync(name, fn) {
  try {
    const problem = await fn();
    if (problem) { failures.push(`${name}: ${problem}`); process.stdout.write('x'); }
    else { passed++; process.stdout.write('.'); }
  } catch (err) {
    failures.push(`${name}: threw ${err.message}`);
    process.stdout.write('x');
  }
}

const chrome = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';

function renderBadge(page) {
  const dom = execFileSync(chrome, ['--headless=new', '--disable-gpu', '--virtual-time-budget=15000',
    '--dump-dom', `${BASE}/${page}.html`], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
  const m = dom.match(/id="sourceBadge"[^>]*>([^<]*)/);
  return { badge: m ? m[1].trim() : null, dom };
}

async function main() {
  // ---- static analysis, no server needed ----
  for (const f of fs.readdirSync(ROOT).filter((n) => n.endsWith('.html'))) {
    const src = fs.readFileSync(path.join(ROOT, f), 'utf8');
    const blocks = src.match(/<script>([\s\S]*?)<\/script>/g) || [];
    check(`${f} inline script parses`, () => {
      for (const b of blocks) {
        const body = b.replace(/^<script>/, '').replace(/<\/script>$/, '');
        const tmp = path.join(require('os').tmpdir(), `smoke-${process.pid}.js`);
        fs.writeFileSync(tmp, body);
        try { execFileSync(process.execPath, ['--check', tmp], { stdio: 'ignore' }); }
        catch { return 'syntax error in inline script'; }
        finally { fs.unlinkSync(tmp); }
      }
      return null;
    });
  }

  check('no credentials committed', () => {
    const tracked = execFileSync('git', ['ls-files'], { cwd: ROOT, encoding: 'utf8' }).split('\n').filter(Boolean);
    const banned = tracked.filter((f) => /\.env$|contrast-client\.json$|\.pem$|\.key$/.test(f));
    return banned.length ? `tracked secret files: ${banned.join(', ')}` : null;
  });

  // ---- boot the server in mock mode ----
  const server = spawn(process.execPath, ['server.js'], {
    cwd: ROOT, env: { ...process.env, MOCK: '1', PORT: String(PORT) }, stdio: ['ignore', 'pipe', 'pipe'],
  });
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('server did not start in 10s')), 10000);
    server.stdout.on('data', (d) => { if (String(d).includes('Reports at')) { clearTimeout(timer); resolve(); } });
    server.on('exit', (c) => { clearTimeout(timer); reject(new Error(`server exited early (${c})`)); });
  });

  try {
    // ---- endpoints ----
    const expect = {
      '/api/vulnerabilities': (d) => (typeof d.total === 'number' && d.bySeverity && Array.isArray(d.items) ? null : 'missing total/bySeverity/items'),
      '/api/routes': (d) => (d.totals && Array.isArray(d.apps) ? null : 'missing totals/apps'),
      '/api/libraries': (d) => (d.totals && d.grades && Array.isArray(d.items) ? null : 'missing totals/grades/items'),
      '/api/cves': (d) => (Array.isArray(d.list) && d.detail ? null : 'missing list/detail'),
      '/api/attacks': (d) => (d.totals && Array.isArray(d.items) ? null : 'missing totals/items'),
      '/api/compliance': (d) => (d.totals && d.bySeverity && d.sla ? null : 'missing totals/bySeverity/sla'),
      '/api/vulnerability': (d) => (Array.isArray(d.list) && d.detail ? null : 'missing list/detail'),
    };
    for (const [route, validate] of Object.entries(expect)) {
      await checkAsync(`GET ${route}`, async () => {
        const res = await fetch(BASE + route);
        if (!res.ok) return `HTTP ${res.status}`;
        const d = await res.json();
        if (d.source !== 'mock') return `expected mock source, got ${d.source}`;
        return validate(d);
      });
    }

    await checkAsync('bad CVE id is rejected', async () => {
      const res = await fetch(`${BASE}/api/cves?id=not-a-cve`);
      return res.status === 502 ? null : `expected 502, got ${res.status}`;
    });

    // ---- the file server must never expose anything but pages ----
    const mustNotServe = ['.contrast-client.json', '.env', 'package.json', 'server.js',
                          'lib/mcp.js', 'scripts/login.js', 'fixtures/routes.json',
                          '.git/config', '../server.js'];
    for (const p of mustNotServe) {
      await checkAsync(`refuses /${p}`, async () => {
        const res = await fetch(`${BASE}/${p}`);
        return res.status === 404 ? null : `served with HTTP ${res.status}`;
      });
    }

    await checkAsync('serves index', async () => {
      const res = await fetch(BASE + '/');
      return res.ok && (await res.text()).includes('<html') ? null : `HTTP ${res.status}`;
    });

    // ---- pages actually render ----
    if (!SKIP_UI && fs.existsSync(chrome)) {
      for (const page of LIVE_PAGES) {
        await checkAsync(`${page} reaches a terminal state`, async () => {
          const { badge } = renderBadge(page);
          if (!badge) return 'no source badge found';
          if (badge === 'Loading') return 'stuck on Loading, the script probably threw';
          return ['MOCK DATA', 'LIVE', 'SNAPSHOT'].includes(badge) ? null : `unexpected badge "${badge}"`;
        });
      }
    }
  } finally {
    server.kill();
  }

  console.log(`\n\n${passed} passed, ${failures.length} failed`);
  if (failures.length) {
    failures.forEach((f) => console.error('  FAIL ' + f));
    process.exit(1);
  }
}

main().catch((err) => { console.error(err); process.exit(1); });
