#!/usr/bin/env node
// Does the browser survive a large organization?
//
// The demo org has 8 applications and 27 findings, so neither the smoke suite
// nor the unit tests can answer that. This generates a synthetic enterprise
// org, serves it through mock mode, and asserts each page stays within a DOM
// budget. A page that renders every row of a big result set becomes unusable
// long before it becomes incorrect.
//
// Run: npm run test:scale

const { spawn, execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const PORT = Number(process.env.SCALE_PORT || 3997);
const BASE = `http://127.0.0.1:${PORT}`;
const CHROME = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';

// Generous ceilings: comfortably above what a capped page produces, well below
// what an uncapped one does.
const BUDGET = {
  poc_generator: 4000,
  smartfix_guide: 4000,
  library_security: 9000,
  vulnerability_dashboard: 9000,
  compliance_mttr: 4000,
  cve_impact: 4000,
  route_coverage: 9000,
};

let rng = 7;
const rand = (n) => { rng = (rng * 1103515245 + 12345) & 0x7fffffff; return rng % n; };

function synthesise(dir) {
  fs.mkdirSync(dir, { recursive: true });

  const libs = [];
  for (let i = 0; i < 2000; i++) {
    const ncve = i < 1200 ? [0, 0, 1, 2, 3, 8, 20][rand(7)] : 0;
    libs.push({
      name: `lib-${i}.jar`, group: `com.example.p${i % 50}`, version: '1.0',
      latestVersion: '9.9.9', grade: 'ABCDF'[rand(5)],
      classCount: 100 + rand(1900), classesUsed: rand(400),
      monthsOutdated: rand(80), language: 'Java',
      total: ncve, critical: Math.min(ncve, 3), high: Math.max(0, ncve - 3),
      medium: 0, low: 0, note: 0,
      cves: Array.from({ length: ncve }, (_, j) => ({
        id: `CVE-2024-${10000 + j}`, severity: 'HIGH', description: 'Synthetic. '.repeat(12),
      })),
      apps: [`app-${rand(200)}`],
    });
  }
  fs.writeFileSync(path.join(dir, 'libraries.json'), JSON.stringify(libs));

  const sev = ['Critical', 'High', 'Medium', 'Low', 'Note'];
  const vulns = Array.from({ length: 5000 }, (_, i) => ({
    id: `V-${i}`, title: `Synthetic finding ${i} on /api/path/${i % 300}`,
    type: ['sql-injection', 'reflected-xss', 'crypto-bad-mac'][rand(3)],
    severity: sev[rand(5)], app: `app-${rand(200)}`, appId: 'a'.repeat(8),
    status: 'Reported', environments: ['PRODUCTION'],
    firstSeenAt: '2026-08-01T00:00:00+00:00', lastSeenAt: '2026-10-01T00:00:00+00:00', closedAt: null,
  }));
  fs.writeFileSync(path.join(dir, 'vulnerabilities.json'), JSON.stringify(vulns));

  // The PoC and SmartFix pages put every finding into one <select>.
  fs.writeFileSync(path.join(dir, 'vulnerability.json'), JSON.stringify({
    list: vulns,
    detail: {
      id: 'V-0', appId: 'a', app: 'app-1', title: 'Synthetic finding 0', type: 'sql-injection',
      severity: 'Critical', status: 'Reported', environments: ['PRODUCTION'],
      firstSeenAt: '2026-08-01T00:00:00+00:00', lastSeenAt: '2026-10-01T00:00:00+00:00',
      httpRequest: 'GET /x HTTP/1.1\nHost: example\n\n', howToFix: 'Synthetic.',
      remediationHint: 'Synthetic.', stackTrace: [], vulnerableLibraries: [],
    },
  }));

  const routes = Array.from({ length: 200 }, (_, i) => ({
    name: `app-${i}`, appId: `id-${i}`, language: 'Java', status: 'online',
    totalRoutes: 40, exercised: 18, discovered: 22, coveragePercent: 45,
    vulnerabilities: rand(5), criticalVulnerabilities: 0,
    routes: Array.from({ length: 40 }, (_, r) => ({ url: `/api/r${r}`, verb: 'GET', status: 'EXERCISED', vulnerabilities: 0 })),
  }));
  fs.writeFileSync(path.join(dir, 'routes.json'), JSON.stringify(routes));

  // These are small regardless of org size; copy the real ones through.
  for (const f of ['attacks.json', 'cves.json', 'tools.json', 'captured.json']) {
    const src = path.join(ROOT, 'fixtures', f);
    if (fs.existsSync(src)) fs.copyFileSync(src, path.join(dir, f));
  }
}

async function main() {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'contrast-scale-'));
  const fixtures = path.join(tmp, 'fixtures');
  synthesise(fixtures);

  // Run the server against a copy of the repo whose fixtures are the big ones.
  const stage = path.join(tmp, 'app');
  fs.mkdirSync(stage);
  for (const entry of fs.readdirSync(ROOT)) {
    if (['node_modules', '.git', 'fixtures', 'test'].includes(entry)) continue;
    fs.cpSync(path.join(ROOT, entry), path.join(stage, entry), { recursive: true });
  }
  fs.cpSync(fixtures, path.join(stage, 'fixtures'), { recursive: true });

  const server = spawn(process.execPath, ['server.js'], {
    cwd: stage, env: { ...process.env, MOCK: '1', PORT: String(PORT) }, stdio: ['ignore', 'pipe', 'pipe'],
  });
  await new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('server did not start')), 10000);
    server.stdout.on('data', (d) => { if (String(d).includes('Reports at')) { clearTimeout(t); resolve(); } });
    server.on('exit', (c) => { clearTimeout(t); reject(new Error(`server exited (${c})`)); });
  });

  const failures = [];
  let passed = 0;
  console.log('  Synthetic org: 2,000 libraries (~830 with CVEs), 5,000 findings, 200 applications\n');
  console.log(`  ${'page'.padEnd(26)}${'divs'.padStart(8)}${'DOM'.padStart(10)}${'time'.padStart(8)}  budget`);

  try {
    for (const [page, budget] of Object.entries(BUDGET)) {
      const started = Date.now();
      let dom = '';
      try {
        dom = execFileSync(CHROME, ['--headless=new', '--disable-gpu', '--virtual-time-budget=60000',
          '--dump-dom', `${BASE}/${page}.html`], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], maxBuffer: 64 * 1024 * 1024 });
      } catch (err) {
        failures.push(`${page}: browser failed, ${err.message.split('\n')[0]}`);
        continue;
      }
      const secs = ((Date.now() - started) / 1000).toFixed(1);
      const divs = (dom.match(/<div/g) || []).length;
      const mb = (Buffer.byteLength(dom) / 1048576).toFixed(2);
      const ok = divs <= budget;
      console.log(`  ${page.padEnd(26)}${String(divs).padStart(8)}${(mb + ' MB').padStart(10)}${(secs + 's').padStart(8)}  ${ok ? 'ok' : 'OVER ' + budget}`);
      if (ok) passed++; else failures.push(`${page}: ${divs} divs exceeds the ${budget} budget; the page renders every row`);
    }
  } finally {
    server.kill();
    fs.rmSync(tmp, { recursive: true, force: true });
  }

  console.log(`\n  ${passed} within budget, ${failures.length} over`);
  if (failures.length) { failures.forEach((f) => console.error('  FAIL ' + f)); process.exit(1); }
}

main().catch((e) => { console.error(e); process.exit(1); });
