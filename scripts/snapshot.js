#!/usr/bin/env node
// Rebuilds the *_static.html fallbacks from live data.
//
// The originals were hand-written snapshots full of invented content: a world
// map plotting private 10.x addresses on US cities, an MTTR for an org with no
// remediated findings, library counts that were wrong by a factor of three.
// They are what GitHub Pages serves and what every error links to, so the most
// likely thing a stranger sees was the fiction rather than the fix.
//
// Each snapshot is now the real page with a real API response frozen into it.
// assets/reports.js notices the frozen payload, serves it instead of fetching,
// and labels the page with its capture date.
//
// Run: npm run snapshot   (needs a live session and the server running)

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const BASE = process.env.SNAPSHOT_BASE || 'http://127.0.0.1:3000';

const PAGES = {
  vulnerability_dashboard: '/api/vulnerabilities',
  route_coverage: '/api/routes',
  library_security: '/api/libraries',
  cve_impact: '/api/cves',
  attack_activity: '/api/attacks',
  compliance_mttr: '/api/compliance',
  poc_generator: '/api/vulnerability',
  smartfix_guide: '/api/vulnerability',
};

async function main() {
  const capturedAt = new Date().toISOString();
  let failed = 0;

  for (const [page, endpoint] of Object.entries(PAGES)) {
    process.stdout.write(`  ${page.padEnd(26)}`);
    try {
      const res = await fetch(BASE + endpoint);
      if (!res.ok) throw new Error(`API returned ${res.status}`);
      const payload = await res.json();
      if (payload.source !== 'live') throw new Error(`expected live data, got ${payload.source}`);

      const src = fs.readFileSync(path.join(ROOT, `${page}.html`), 'utf8');
      const marker = '<script src="assets/reports.js"></script>';
      if (!src.includes(marker)) throw new Error('page does not load the shared module');

      const frozen = `<script>window.FROZEN_DATA = ${JSON.stringify({ capturedAt, payload })
        .replace(/</g, '\\u003c')};</script>\n    ${marker}`;
      fs.writeFileSync(path.join(ROOT, `${page}_static.html`), src.replace(marker, frozen));

      const kb = Math.round(fs.statSync(path.join(ROOT, `${page}_static.html`)).size / 102.4) / 10;
      console.log(`ok  ${kb} KB`);
    } catch (err) {
      console.log(`FAILED  ${err.message}`);
      failed++;
    }
  }

  console.log(`\nCaptured ${capturedAt}`);
  if (failed) { console.error(`${failed} snapshot(s) failed.`); process.exit(1); }
}

main().catch((err) => { console.error(err.message); process.exit(1); });
