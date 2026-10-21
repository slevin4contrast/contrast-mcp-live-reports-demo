#!/usr/bin/env node
// What does a customer see when there is nothing to show?
//
// An organization without ADR has no attacks; one without CVE Shield has no CVE
// data; a fresh one has nothing at all. Those pages used to render blank, which
// is indistinguishable from a broken page. Each should say what is missing and
// what to check.
//
// Run: npm run test:empty

const { spawn, execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const PORT = Number(process.env.EMPTY_PORT || 3996);
const BASE = `http://127.0.0.1:${PORT}`;
const CHROME = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';

const PAGES = ['vulnerability_dashboard', 'route_coverage', 'library_security', 'cve_impact',
               'attack_activity', 'compliance_mttr', 'poc_generator', 'smartfix_guide'];

const EMPTY = {
  'vulnerabilities.json': [],
  'routes.json': [],
  'libraries.json': [],
  'attacks.json': [],
  'cves.json': { list: [], detail: null },
  'vulnerability.json': { list: [], detail: null },
  'tools.json': [],
};

async function main() {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'contrast-empty-'));
  const stage = path.join(tmp, 'app');
  fs.mkdirSync(stage);
  for (const entry of fs.readdirSync(ROOT)) {
    if (['node_modules', '.git', 'fixtures', 'test'].includes(entry)) continue;
    fs.cpSync(path.join(ROOT, entry), path.join(stage, entry), { recursive: true });
  }
  fs.mkdirSync(path.join(stage, 'fixtures'));
  for (const [name, body] of Object.entries(EMPTY)) {
    fs.writeFileSync(path.join(stage, 'fixtures', name), JSON.stringify(body));
  }
  fs.writeFileSync(path.join(stage, 'fixtures', 'captured.json'),
    JSON.stringify({ capturedAt: new Date().toISOString(), sets: [] }));

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
  console.log('  Every data source empty, as for an org without the relevant licence\n');

  try {
    for (const page of PAGES) {
      let dom = '';
      try {
        dom = execFileSync(CHROME, ['--headless=new', '--disable-gpu', '--virtual-time-budget=20000',
          '--dump-dom', `${BASE}/${page}.html`], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
      } catch (err) {
        failures.push(`${page}: browser failed`);
        continue;
      }
      const body = dom.replace(/<script[\s\S]*?<\/script>/g, '');
      const hasState = /class="empty-state"/.test(body);
      const badge = (dom.match(/id="sourceBadge"[^>]*>([^<]*)/) || [])[1] || '?';
      console.log(`  ${page.padEnd(26)} badge=${badge.padEnd(11)} ${hasState ? 'explains itself' : 'BLANK'}`);
      if (hasState && badge !== 'Loading') passed++;
      else failures.push(`${page}: renders nothing to explain why it is empty`);
    }
  } finally {
    server.kill();
    fs.rmSync(tmp, { recursive: true, force: true });
  }

  console.log(`\n  ${passed} explain themselves, ${failures.length} do not`);
  if (failures.length) { failures.forEach((f) => console.error('  FAIL ' + f)); process.exit(1); }
}

main().catch((e) => { console.error(e); process.exit(1); });
