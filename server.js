// Local demo server. Serves the report pages and proxies the Contrast MCP
// server, so the OAuth token stays on this machine. Bound to localhost only.
const http = require('http');
const fs = require('fs');
const path = require('path');
const contrast = require('./lib/mcp');

const PORT = process.env.PORT || 3000;
const MOCK = process.env.MOCK === '1' || !contrast.configured();
const TYPES = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json', '.png': 'image/png', '.svg': 'image/svg+xml' };

function summarize(items) {
  const order = ['Critical', 'High', 'Medium', 'Low', 'Note'];
  const bySeverity = Object.fromEntries(order.map((s) => [s, 0]));
  const byApp = {};
  items.forEach((v) => {
    bySeverity[v.severity] = (bySeverity[v.severity] || 0) + 1;
    byApp[v.app] = byApp[v.app] || Object.fromEntries(order.map((s) => [s, 0]));
    byApp[v.app][v.severity] = (byApp[v.app][v.severity] || 0) + 1;
  });
  return { total: items.length, bySeverity, byApp };
}

const routes = {
  '/api/vulnerabilities': async () => {
    const items = MOCK ? contrast.loadFixture('vulnerabilities') : await contrast.listVulnerabilities();
    return { source: MOCK ? 'mock' : 'live', generatedAt: new Date().toISOString(), ...summarize(items), items };
  },
  // Remediation SLA in days per severity. This is an assumed policy, not a
  // value Contrast stores, and the page states it so the numbers can be checked.
  '/api/compliance': async () => {
    const SLA = { Critical: 7, High: 30, Medium: 90, Low: 180, Note: 180 };
    const items = MOCK ? contrast.loadFixture('vulnerabilities') : await contrast.listVulnerabilities({ allStatuses: true });
    const now = Date.now();
    const DAY = 86400000;
    const open = [];
    const closed = [];

    items.forEach((v) => {
      const first = v.firstSeenAt ? Date.parse(v.firstSeenAt) : null;
      const shut = v.closedAt ? Date.parse(v.closedAt) : null;
      const row = {
        ...v,
        ageDays: first ? Math.floor(((shut || now) - first) / DAY) : null,
        sla: SLA[v.severity] ?? 180,
      };
      row.breached = row.ageDays != null && row.ageDays > row.sla;
      (shut ? closed : open).push(row);
    });

    const order = ['Critical', 'High', 'Medium', 'Low', 'Note'];
    const bySeverity = {};
    order.forEach((s) => {
      const rows = open.filter((v) => v.severity === s);
      const ages = rows.map((v) => v.ageDays).filter((n) => n != null).sort((a, b) => a - b);
      bySeverity[s] = {
        open: rows.length,
        breached: rows.filter((v) => v.breached).length,
        slaDays: SLA[s],
        medianAge: ages.length ? ages[Math.floor(ages.length / 2)] : null,
        oldestAge: ages.length ? ages[ages.length - 1] : null,
      };
    });

    const buckets = { '0-7 days': 0, '8-30 days': 0, '31-90 days': 0, '90+ days': 0 };
    open.forEach((v) => {
      const d = v.ageDays ?? 0;
      if (d <= 7) buckets['0-7 days']++;
      else if (d <= 30) buckets['8-30 days']++;
      else if (d <= 90) buckets['31-90 days']++;
      else buckets['90+ days']++;
    });

    const mttrDays = closed.length
      ? Math.round(closed.reduce((n, v) => n + (v.ageDays || 0), 0) / closed.length)
      : null;
    const allAges = open.map((v) => v.ageDays).filter((n) => n != null).sort((a, b) => a - b);

    return {
      source: MOCK ? 'mock' : 'live',
      generatedAt: new Date().toISOString(),
      sla: SLA,
      totals: {
        total: items.length,
        open: open.length,
        closed: closed.length,
        mttrDays,
        breached: open.filter((v) => v.breached).length,
        slaCompliance: open.length ? Math.round(((open.length - open.filter((v) => v.breached).length) / open.length) * 100) : 100,
        medianAge: allAges.length ? allAges[Math.floor(allAges.length / 2)] : null,
        oldestAge: allAges.length ? allAges[allAges.length - 1] : null,
      },
      bySeverity, buckets,
      oldest: open.slice().sort((a, b) => (b.ageDays || 0) - (a.ageDays || 0)).slice(0, 15),
    };
  },
  '/api/vulnerability': async (params) => {
    const id = params && params.get('id');
    const appId = params && params.get('appId');
    if (id && !/^[A-Z0-9-]{4,40}$/i.test(id)) throw new Error(`Not a vulnerability id: ${id}`);
    if (appId && !/^[a-f0-9-]{36}$/i.test(appId)) throw new Error('Not an application id');
    const data = MOCK ? contrast.loadFixture('vulnerability') : await contrast.vulnerabilityReport(id || undefined, appId || undefined);
    return { source: MOCK ? 'mock' : 'live', generatedAt: new Date().toISOString(), ...data };
  },
  '/api/attacks': async () => {
    const items = MOCK ? contrast.loadFixture('attacks') : await contrast.listAttacks();
    const byStatus = {};
    const byRule = {};
    const byApp = {};
    const sources = new Set();
    items.forEach((a) => {
      byStatus[a.status] = (byStatus[a.status] || 0) + 1;
      sources.add(a.source);
      a.rules.forEach((r) => { byRule[r] = (byRule[r] || 0) + 1; });
      a.targets.forEach((t) => {
        byApp[t.app] = byApp[t.app] || { exploited: 0, probed: 0, other: 0 };
        const k = t.status === 'EXPLOITED' ? 'exploited' : t.status === 'PROBED' ? 'probed' : 'other';
        byApp[t.app][k]++;
      });
    });
    items.sort((a, b) => (b.probes - a.probes));
    return {
      source: MOCK ? 'mock' : 'live',
      generatedAt: new Date().toISOString(),
      totals: {
        attacks: items.length,
        exploited: byStatus.EXPLOITED || 0,
        probed: byStatus.PROBED || 0,
        blocked: (byStatus.BLOCKED || 0) + (byStatus.BLOCKED_PERIMETER || 0),
        sources: sources.size,
        probes: items.reduce((n, a) => n + (a.probes || 0), 0),
        appsTargeted: Object.keys(byApp).length,
      },
      byStatus, byRule, byApp, items,
    };
  },
  '/api/cves': async (params) => {
    const id = params && params.get('id');
    if (id && !/^CVE-\d{4}-\d{4,19}$/i.test(id)) throw new Error(`Not a CVE id: ${id}`);
    const data = MOCK ? contrast.loadFixture('cves') : await contrast.cveReport(id || undefined);
    return { source: MOCK ? 'mock' : 'live', generatedAt: new Date().toISOString(), ...data };
  },
  '/api/libraries': async () => {
    const items = MOCK ? contrast.loadFixture('libraries') : await contrast.listLibraries();
    const grades = { A: 0, B: 0, C: 0, D: 0, F: 0 };
    const cveIds = new Set();
    let withCves = 0;
    items.forEach((l) => {
      if (l.grade in grades) grades[l.grade]++;
      if (l.total > 0) withCves++;
      l.cves.forEach((c) => cveIds.add(c.id));
    });
    items.sort((a, b) => (b.critical - a.critical) || (b.high - a.high) || (b.total - a.total) || (b.monthsOutdated - a.monthsOutdated));
    return {
      source: MOCK ? 'mock' : 'live',
      generatedAt: new Date().toISOString(),
      totals: {
        libraries: items.length,
        withCves,
        cveInstances: items.reduce((n, l) => n + l.total, 0),
        uniqueCves: cveIds.size,
        critical: items.reduce((n, l) => n + l.critical, 0),
        high: items.reduce((n, l) => n + l.high, 0),
        unusedWithCves: items.filter((l) => l.total > 0 && !l.classesUsed).length,
      },
      grades,
      items,
    };
  },
  '/api/routes': async () => {
    const apps = MOCK ? contrast.loadFixture('routes') : await contrast.listRouteCoverage();
    const sum = (k) => apps.reduce((n, a) => n + a[k], 0);
    const totalRoutes = sum('totalRoutes');
    return {
      source: MOCK ? 'mock' : 'live',
      generatedAt: new Date().toISOString(),
      totals: {
        totalRoutes,
        exercised: sum('exercised'),
        discovered: sum('discovered'),
        coveragePercent: totalRoutes ? Number(((sum('exercised') / totalRoutes) * 100).toFixed(2)) : 0,
        vulnerabilities: sum('vulnerabilities'),
        criticalVulnerabilities: sum('criticalVulnerabilities'),
      },
      apps,
    };
  },
};

http.createServer(async (req, res) => {
  const { pathname, searchParams } = new URL(req.url, 'http://localhost');
  if (routes[pathname]) {
    try {
      const body = JSON.stringify(await routes[pathname](searchParams));
      res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
      return res.end(body);
    } catch (err) {
      console.error(err.message);
      res.writeHead(502, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: err.message }));
    }
  }
  const file = path.normalize(path.join(__dirname, pathname === '/' ? 'index.html' : pathname));
  const rel = path.relative(__dirname, file);
  const top = rel.split(path.sep)[0];
  if (rel.startsWith('..') || ['.env', '.git', 'lib', 'server.js', 'fixtures'].includes(top)) {
    res.writeHead(404); return res.end('Not found');
  }
  fs.readFile(file, (err, data) => {
    if (err) { res.writeHead(404); return res.end('Not found'); }
    res.writeHead(200, { 'Content-Type': TYPES[path.extname(file)] || 'application/octet-stream' });
    res.end(data);
  });
}).listen(PORT, '127.0.0.1', () => {
  console.log(`Reports at http://localhost:${PORT} (${MOCK ? 'MOCK data' : 'LIVE Contrast data'})`);
});
