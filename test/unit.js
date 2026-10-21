#!/usr/bin/env node
// Unit tests for the MCP client's paging and fan-out.
//
// The smoke suite runs against the demo org, which has 8 applications and 27
// findings, so it cannot see the behaviour that matters on a real customer:
// what happens at 5,000 findings or 200 applications. These stub callTool and
// simulate that, with no network.

const assert = require('assert');
const Module = require('module');
const path = require('path');

const LIB = path.join(__dirname, '..', 'lib', 'mcp.js');

let passed = 0;
const failures = [];

async function test(name, fn) {
  try {
    await fn();
    passed++;
    process.stdout.write('.');
  } catch (err) {
    failures.push(`${name}: ${err.message}`);
    process.stdout.write('x');
  }
}

// Load a fresh copy of the module with callTool replaced.
function loadWithStub(stub) {
  delete require.cache[require.resolve(LIB)];
  const mcp = require(LIB);
  const calls = [];
  const wrapped = async (name, args) => {
    calls.push({ name, args, at: Date.now() });
    return stub(name, args, calls.length);
  };
  // Rebind the module's internal callTool by re-evaluating with an override.
  mcp.__setCallTool(wrapped);
  return { mcp, calls };
}

function fakeVulns(total) {
  return (name, args) => {
    if (name !== 'search_vulnerabilities') throw new Error(`unexpected tool ${name}`);
    const size = args.pageSize;
    const start = (args.page - 1) * size;
    const items = [];
    for (let i = start; i < Math.min(start + size, total); i++) {
      items.push({ vulnID: `V-${i}`, title: `finding ${i}`, severity: 'Medium', appName: 'app', appID: 'a', status: 'Reported' });
    }
    return { items, totalItems: total, hasMorePages: start + size < total };
  };
}

async function main() {
  // ---- paging ----
  await test('small org: pages until exhausted', async () => {
    const { mcp, calls } = loadWithStub(fakeVulns(120));
    const out = await mcp.listVulnerabilities();
    assert.strictEqual(out.items.length, 120, `got ${out.items.length}`);
    assert.strictEqual(calls.length, 3, `expected 3 pages, made ${calls.length}`);
    assert.strictEqual(out.truncated, false);
  });

  await test('large org: returns everything, not a silent 1000', async () => {
    const { mcp } = loadWithStub(fakeVulns(5000));
    const out = await mcp.listVulnerabilities();
    assert.strictEqual(out.items.length, 5000, `truncated to ${out.items.length}`);
    assert.strictEqual(out.truncated, false);
  });

  await test('beyond the ceiling: truncates but says so', async () => {
    const { mcp } = loadWithStub(fakeVulns(60000));
    const out = await mcp.listVulnerabilities();
    assert.ok(out.truncated === true, 'expected truncated flag');
    assert.ok(out.items.length < 60000, 'should have stopped');
    assert.ok(out.limit > 0, 'expected a stated limit');
  });

  await test('a last page that overshoots the ceiling is not called truncated', async () => {
    // 27 findings, ceiling of 10: one page returns everything, so nothing was
    // lost and claiming otherwise would be a false alarm.
    process.env.CONTRAST_MAX_ITEMS = '10';
    try {
      const { mcp } = loadWithStub(fakeVulns(27));
      const out = await mcp.listVulnerabilities();
      assert.strictEqual(out.items.length, 27);
      assert.strictEqual(out.truncated, false, 'nothing was dropped, so this must not warn');
    } finally {
      delete process.env.CONTRAST_MAX_ITEMS;
    }
  });

  await test('a ceiling that really does cut results says so', async () => {
    process.env.CONTRAST_MAX_ITEMS = '60';
    try {
      const { mcp } = loadWithStub(fakeVulns(500));
      const out = await mcp.listVulnerabilities();
      assert.strictEqual(out.truncated, true, 'results were cut, so it must warn');
      assert.ok(out.items.length < 500);
    } finally {
      delete process.env.CONTRAST_MAX_ITEMS;
    }
  });

  await test('CVE search follows the cursor to the end', async () => {
    // search_cves pages by cursor, not page number. Fetching one page meant an
    // org with 177 CVEs showed 25 and hid the rest with no way through.
    const TOTAL = 177;
    const { mcp, calls } = loadWithStub(async (name, args) => {
      if (name !== 'search_cves') return { data: {} };
      const start = args.cursor ? Number(args.cursor) : 0;
      const size = args.pageSize || 25;
      const items = [];
      for (let i = start; i < Math.min(start + size, TOTAL); i++) {
        items.push({ cveId: `CVE-2024-${1000 + i}`, maxScore: 9, highestShieldStatus: 'NOT_SEEN', numApplications: 1 });
      }
      const next = start + size;
      return { items, totalItems: TOTAL, hasMore: next < TOTAL, nextCursor: next < TOTAL ? String(next) : null };
    });
    const out = await mcp.searchAllCves();
    assert.strictEqual(out.items.length, TOTAL, `got ${out.items.length} of ${TOTAL}`);
    assert.ok(calls.length > 1, 'should have followed the cursor');
  });

  // ---- fan-out ----
  await test('route coverage runs applications concurrently', async () => {
    let inFlight = 0;
    let peak = 0;
    const { mcp, calls } = loadWithStub(async (name) => {
      if (name === 'search_applications') {
        return { items: Array.from({ length: 40 }, (_, i) => ({ appID: `a${i}`, name: `app${i}`, language: 'Java', status: 'online' })) };
      }
      inFlight++; peak = Math.max(peak, inFlight);
      await new Promise((r) => setTimeout(r, 20));
      inFlight--;
      return { data: { totalRoutes: 1, exercisedCount: 1, discoveredCount: 0, coveragePercent: 100, totalVulnerabilities: 0, totalCriticalVulnerabilities: 0, routes: [] } };
    });
    const started = Date.now();
    const apps = await mcp.listRouteCoverage();
    const ms = Date.now() - started;
    assert.strictEqual(apps.length, 40);
    assert.ok(peak > 1, `ran sequentially, peak concurrency was ${peak}`);
    assert.ok(peak <= 8, `too concurrent, peak was ${peak}`);
    assert.ok(ms < 40 * 20 * 0.6, `took ${ms}ms, barely better than sequential`);
    assert.strictEqual(calls.length, 41);
  });

  await test('one failing application does not sink the page', async () => {
    const { mcp } = loadWithStub(async (name, args) => {
      if (name === 'search_applications') {
        return { items: [{ appID: 'ok', name: 'fine' }, { appID: 'bad', name: 'broken' }] };
      }
      if (args.appId === 'bad') throw new Error('no Assess licence');
      return { data: { totalRoutes: 2, exercisedCount: 1, discoveredCount: 1, coveragePercent: 50, totalVulnerabilities: 0, totalCriticalVulnerabilities: 0, routes: [] } };
    });
    const apps = await mcp.listRouteCoverage();
    assert.strictEqual(apps.length, 2);
    const broken = apps.find((a) => a.name === 'broken');
    assert.ok(broken.error, 'the failing app should carry its error');
    assert.strictEqual(broken.totalRoutes, 0);
  });

  await test('libraries fan out concurrently too', async () => {
    let inFlight = 0; let peak = 0;
    const { mcp } = loadWithStub(async (name) => {
      if (name === 'search_applications') {
        return { items: Array.from({ length: 20 }, (_, i) => ({ appID: `a${i}`, name: `app${i}` })) };
      }
      inFlight++; peak = Math.max(peak, inFlight);
      await new Promise((r) => setTimeout(r, 15));
      inFlight--;
      return { items: [{ hash: 'h1', fileName: 'x.jar', version: '1', totalVulnerabilities: 0, vulnerabilities: [] }], hasMorePages: false };
    });
    const libs = await mcp.listLibraries();
    assert.ok(peak > 1, `libraries ran sequentially, peak ${peak}`);
    assert.strictEqual(libs.length, 1, 'should dedupe by hash');
    assert.strictEqual(libs[0].apps.length, 20, 'should record every app using it');
  });

  // ---- credential sources, the part that decides whether Windows works ----
  await test('an explicit token is used without touching the keychain', async () => {
    const cp = require('child_process');
    const realExec = cp.execFileSync;
    cp.execFileSync = (cmd, ...rest) => {
      if (cmd === 'security') throw new Error('keychain must not be consulted');
      return realExec(cmd, ...rest);
    };
    process.env.CONTRAST_MCP_URL = 'https://example.contrastsecurity.com/mcp';
    process.env.CONTRAST_ACCESS_TOKEN = 'token-from-anywhere';
    try {
      delete require.cache[require.resolve(LIB)];
      const mcp = require(LIB);
      assert.strictEqual(mcp.configured(), true, 'should be configured from env alone');
      const src = mcp.credentialSource();
      assert.strictEqual(src.kind, 'env', `used ${src.kind}`);
      assert.strictEqual(src.serverUrl, 'https://example.contrastsecurity.com/mcp');
    } finally {
      cp.execFileSync = realExec;
      delete process.env.CONTRAST_MCP_URL;
      delete process.env.CONTRAST_ACCESS_TOKEN;
      delete require.cache[require.resolve(LIB)];
    }
  });

  await test('with no source at all, the error explains every option', async () => {
    const cp = require('child_process');
    const realExec = cp.execFileSync;
    cp.execFileSync = (cmd, ...rest) => {
      if (cmd === 'security') throw new Error('not found');
      return realExec(cmd, ...rest);
    };
    const realHome = process.env.HOME;
    process.env.HOME = '/nonexistent-home-for-tests';
    try {
      delete require.cache[require.resolve(LIB)];
      const mcp = require(LIB);
      // configured() is deliberately not asserted here: a machine that has
      // already run npm run login is configured regardless of borrowed tokens.
      let msg = '';
      try { mcp.credentialSource(); } catch (e) { msg = e.message; }
      assert.ok(/claude mcp add/.test(msg), 'should name the setup command');
      assert.ok(/CONTRAST_ACCESS_TOKEN/.test(msg), 'should mention the token escape hatch');
    } finally {
      cp.execFileSync = realExec;
      process.env.HOME = realHome;
      delete require.cache[require.resolve(LIB)];
    }
  });

  console.log(`\n\n${passed} passed, ${failures.length} failed`);
  if (failures.length) { failures.forEach((f) => console.error('  FAIL ' + f)); process.exit(1); }
}

main().catch((e) => { console.error(e); process.exit(1); });
