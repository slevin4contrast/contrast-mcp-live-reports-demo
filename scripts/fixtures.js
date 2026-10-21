#!/usr/bin/env node
// Regenerates fixtures/ from a live Contrast organization.
//
// Fixtures are what MOCK mode serves, so the demo runs offline and on GitHub
// Pages. They are a snapshot, and snapshots rot: the whole reason this project
// exists is that the original pages quoted numbers that had drifted far from
// reality. Each file now records when it was captured, and the pages say so.
//
// Run: npm run fixtures

const fs = require('fs');
const path = require('path');
const contrast = require('../lib/mcp');

const OUT = path.join(__dirname, '..', 'fixtures');

const SETS = {
  vulnerabilities: async () => (await contrast.listVulnerabilities({ allStatuses: true })).items,
  routes: () => contrast.listRouteCoverage(),
  attacks: () => contrast.listAttacks(),
  cves: () => contrast.cveReport(),
  vulnerability: () => contrast.vulnerabilityReport(),
  tools: () => contrast.listTools(),
  // Libraries is the big one. Keep every library carrying a CVE, plus a sample
  // of clean ones, so the file stays a sensible size without hiding the risk.
  libraries: async () => {
    const all = await contrast.listLibraries();
    const risky = all.filter((l) => l.total > 0);
    const clean = all.filter((l) => l.total === 0).slice(0, 40);
    return risky.concat(clean);
  },
};

async function main() {
  if (!contrast.configured()) {
    console.error('No Contrast session. Run npm run login first.');
    process.exit(1);
  }

  const only = process.argv.slice(2).filter((a) => !a.startsWith('-'));
  const names = only.length ? only : Object.keys(SETS);
  const capturedAt = new Date().toISOString();
  let failed = 0;

  for (const name of names) {
    if (!SETS[name]) { console.error(`  unknown fixture: ${name}`); failed++; continue; }
    process.stdout.write(`  ${name.padEnd(16)}`);
    try {
      const data = await SETS[name]();
      const file = path.join(OUT, `${name}.json`);
      fs.writeFileSync(file, JSON.stringify(data, null, 1));
      const rows = Array.isArray(data) ? data.length : Object.keys(data).length;
      const kb = Math.round(fs.statSync(file).size / 102.4) / 10;
      console.log(`ok  ${String(rows).padStart(4)} rows  ${kb} KB`);
    } catch (err) {
      console.log(`FAILED  ${err.message}`);
      failed++;
    }
  }

  fs.writeFileSync(path.join(OUT, 'captured.json'), JSON.stringify({ capturedAt, sets: names }, null, 2));
  console.log(`\nCaptured ${capturedAt}`);
  if (failed) { console.error(`${failed} fixture(s) failed; the rest were written.`); process.exit(1); }
}

main().catch((err) => { console.error(err.message); process.exit(1); });
