// Calls the Contrast MCP server directly. Same tools, same responses the MCP
// returns in chat, so there is no second API client to keep in sync.
//
// Two ways to authenticate, in order of preference:
//
// 1. Own credentials (.contrast-client.json, written by `npm run setup`).
//    The server holds its own OAuth client and mints access tokens via the
//    client_credentials grant, renewing them before they lapse. Nothing
//    expires mid-demo and Claude Code is not involved at all.
//
// 2. Borrowed token from the macOS keychain, the fallback when setup has not
//    been run. Claude Code's access token lasts about 15 minutes.
//
// In mode 2 do NOT add a refresh_token grant. This authorization server rotates
// refresh tokens, so refreshing here invalidates the one Claude Code stored and
// breaks its MCP connection until the user re-runs /mcp. That is precisely what
// mode 1 exists to avoid.
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const SERVER_NAME = 'contrast-hosted-mcp';
const CLIENT_FILE = path.join(__dirname, '..', '.contrast-client.json');

function ownClient() {
  try {
    return JSON.parse(fs.readFileSync(CLIENT_FILE, 'utf8'));
  } catch {
    return null;
  }
}

// Cached token for mode 1. Renewed a minute early so a request never races the clock.
let minted = { token: null, expiresAt: 0 };

async function mintToken(cfg) {
  if (minted.token && Date.now() < minted.expiresAt) return minted.token;

  const res = await fetch(cfg.tokenEndpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'client_credentials',
      client_id: cfg.clientId,
      client_secret: cfg.clientSecret,
      scope: 'openid profile',
    }),
  });
  if (!res.ok) {
    throw new Error(`Could not mint a token (${res.status}). Re-run npm run setup, or delete .contrast-client.json to fall back to the Claude Code token.`);
  }
  const tok = await res.json();
  minted = {
    token: tok.access_token,
    expiresAt: Date.now() + Math.max(30, (tok.expires_in || 900) - 60) * 1000,
  };
  return minted.token;
}

function credentials() {
  const raw = execFileSync('security', ['find-generic-password', '-s', 'Claude Code-credentials', '-w'], { encoding: 'utf8' });
  const entry = Object.values(JSON.parse(raw).mcpOAuth || {}).find((e) => e.serverName === SERVER_NAME);
  if (!entry) throw new Error(`No stored credentials for ${SERVER_NAME}. Run /mcp in Claude Code to connect it.`);
  return entry;
}

function configured() {
  if (ownClient()) return true;
  try {
    credentials();
    return true;
  } catch {
    return false;
  }
}

// Returns the bearer token and the MCP url, from whichever mode is available.
async function auth() {
  const cfg = ownClient();
  if (cfg) return { accessToken: await mintToken(cfg), serverUrl: cfg.serverUrl };
  const entry = credentials();
  return { accessToken: entry.accessToken, serverUrl: entry.serverUrl };
}

let id = 0;

async function callTool(name, args = {}) {
  const { accessToken, serverUrl } = await auth();
  const res = await fetch(serverUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json, text/event-stream',
      Authorization: `Bearer ${accessToken}`,
    },
    body: JSON.stringify({ jsonrpc: '2.0', id: ++id, method: 'tools/call', params: { name, arguments: args } }),
  });
  if (res.status === 401) {
    if (ownClient()) {
      // Our own token went stale early; drop the cache so the next call mints a fresh one.
      minted = { token: null, expiresAt: 0 };
      throw new Error('Contrast rejected the token. Retrying will mint a new one; if it persists, re-run npm run setup.');
    }
    throw new Error('Contrast MCP token expired. Run /mcp in Claude Code to reauthorize.');
  }
  if (!res.ok) throw new Error(`Contrast MCP returned ${res.status} for ${name}`);

  const body = await res.text();
  // The endpoint answers with JSON, or with SSE when it streams.
  const payload = res.headers.get('content-type')?.includes('event-stream')
    ? JSON.parse(body.split('\n').filter((l) => l.startsWith('data:')).pop().slice(5))
    : JSON.parse(body);

  if (payload.error) throw new Error(`${name}: ${payload.error.message}`);
  const text = payload.result?.content?.[0]?.text;
  if (!text) throw new Error(`${name} returned no content`);
  return JSON.parse(text);
}

// allStatuses includes remediated and closed findings, which the tool leaves out
// by default. Needed for anything that measures remediation.
async function listVulnerabilities({ allStatuses = false } = {}) {
  const out = [];
  const statuses = 'Reported,Suspicious,Confirmed,NotAProblem,Remediated,Fixed,AutoRemediated';
  for (let page = 1; page <= 20; page++) {
    const args = { page, pageSize: 50 };
    if (allStatuses) args.statuses = statuses;
    const res = await callTool('search_vulnerabilities', args);
    out.push(...(res.items || []).map((v) => ({
      id: v.vulnID,
      title: v.title,
      type: v.type,
      severity: v.severity,
      app: v.appName,
      appId: v.appID,
      status: v.status,
      environments: v.environments || [],
      firstSeenAt: v.firstSeenAt,
      lastSeenAt: v.lastSeenAt,
      closedAt: v.closedAt,
    })));
    if (!res.hasMorePages) break;
  }
  return out;
}

// One vulnerability in full, plus the list for the picker. With no id it picks
// the most severe finding, since that is what a demo wants to open on.
const SEV_RANK = { Critical: 0, High: 1, Medium: 2, Low: 3, Note: 4 };

async function vulnerabilityReport(vulnId, appId) {
  const list = (await listVulnerabilities()).sort(
    (a, b) => (SEV_RANK[a.severity] ?? 9) - (SEV_RANK[b.severity] ?? 9) || a.title.localeCompare(b.title),
  );
  const pick = (vulnId && list.find((v) => v.id === vulnId)) || list[0];
  if (!pick) return { list, detail: null };

  const d = (await callTool('get_vulnerability', { vulnId: pick.id, appId: appId || pick.appId })).data || {};

  return {
    list,
    detail: {
      id: d.vulnID || pick.id,
      appId: d.appID || pick.appId,
      app: d.appName,
      title: d.title,
      type: d.type,
      severity: d.severity,
      status: d.status,
      environments: d.environments || [],
      firstSeenAt: d.firstSeenAt,
      lastSeenAt: d.lastSeenAt,
      // Contrast strips sensitive headers and redacts values before returning this.
      httpRequest: d.httpRequest || null,
      howToFix: d.howToFix || null,
      remediationHint: d.remediationHint || null,
      stackTrace: (d.stackTrace || []).map((f) => f.stackTraceLine).filter(Boolean),
      vulnerableLibraries: (d.vulnerableLibraries || []).map((l) => ({
        name: l.fileName || l.filename,
        version: l.version,
        latestVersion: l.latestVersion,
        grade: l.grade,
        monthsOutdated: l.monthsOutdated,
        classesUsed: l.classesUsed,
        classCount: l.classCount,
        total: l.totalVulnerabilities,
        cves: (l.vulnerabilities || []).map((c) => ({ id: c.name, severity: c.severityCode })),
      })),
    },
  };
}

// ADR attack events. Source IPs here are whatever the agent observed, often
// internal addresses, so there is no geography to plot.
async function listAttacks() {
  const out = [];
  for (let page = 1; page <= 20; page++) {
    const res = await callTool('search_attacks', { page, pageSize: 100, quickFilter: 'ALL' });
    out.push(...(res.items || []).map((a) => ({
      id: a.attackId,
      source: a.source,
      status: a.status,
      probes: a.probes,
      rules: a.rules || [],
      startTime: a.startTime,
      endTime: a.endTime,
      targets: (a.applications || []).map((t) => ({
        app: t.applicationName,
        language: t.language,
        severity: t.severity,
        status: t.status,
      })),
    })));
    if (!res.hasMorePages) break;
  }
  return out;
}

// The CVE list, plus full detail for one of them. Pass no cveId and it picks
// the highest-scoring CVE that agents have actually seen exploited.
async function cveReport(cveId) {
  const list = (await callTool('search_cves', { pageSize: 25, sort: 'maxCvssScore,DESC' })).items || [];
  const chosen = cveId
    || (list.find((c) => c.highestShieldStatus === 'EXPLOITED') || list[0] || {}).cveId;
  if (!chosen) return { list, detail: null };

  const impact = (await callTool('get_cve_impact', { cveId: chosen })).data || {};
  const issues = (await callTool('list_cve_issues', { cveId: chosen, pageSize: 100 })).items || [];

  // Classic data, which carries the app/server blast radius and class usage.
  let classic = {};
  try {
    classic = (await callTool('list_applications_by_cve', { cveId: chosen })).data || {};
  } catch {
    classic = {};
  }

  return {
    list,
    detail: {
      cveId: chosen,
      cveUrl: impact.cveUrl,
      risk: impact.risk || {},
      exposure: impact.exposure || {},
      protection: impact.protection || {},
      signals: impact.signals || {},
      impactStats: classic.impactStats || null,
      cvssVector: classic.cve?.cvssv3?.vector || null,
      cwe: classic.cve?.cwe || null,
      apps: (classic.apps || []).map((a) => ({
        name: a.name,
        importance: a.importanceDescription,
        classCount: a.classCount,
        classUsage: a.classUsage,
      })),
      servers: (classic.servers || []).map((s) => ({
        name: s.name, environment: s.environment, status: s.status, path: s.path,
      })),
      issues: issues.map((i) => ({
        issueId: i.issueId,
        app: i.applicationName,
        library: `${i.libraryName} ${i.libraryVersion}`,
        score: i.score,
        severity: i.severity,
        status: i.status,
        shield: i.shieldStatusByEnvironment || {},
      })),
    },
  };
}

// One row per distinct library, with the applications that carry it. The same
// library version shows up under several apps, so dedupe on the Contrast hash.
async function listLibraries() {
  const apps = (await callTool('search_applications', { pageSize: 100 })).items || [];
  const byHash = new Map();

  for (const app of apps) {
    for (let page = 1; page <= 20; page++) {
      const res = await callTool('list_application_libraries', { appId: app.appID, page, pageSize: 50 });
      for (const l of res.items || []) {
        const key = l.hash || `${l.group}:${l.fileName}:${l.version}`;
        if (!byHash.has(key)) {
          byHash.set(key, {
            name: l.fileName || l.filename,
            group: l.group,
            version: l.version,
            latestVersion: l.latestVersion,
            grade: l.grade,
            classCount: l.classCount,
            classesUsed: l.classesUsed,
            monthsOutdated: l.monthsOutdated,
            language: l.appLanguage,
            total: l.totalVulnerabilities,
            critical: l.criticalVulnerabilities,
            high: l.highVulnerabilities,
            medium: l.mediumVulnerabilities,
            low: l.lowVulnerabilities,
            note: l.noteVulnerabilities,
            cves: (l.vulnerabilities || []).map((v) => ({
              id: v.name,
              severity: v.severityCode,
              description: (v.description || '').trim(),
            })),
            apps: [],
          });
        }
        byHash.get(key).apps.push(app.name);
      }
      if (!res.hasMorePages) break;
    }
  }
  return [...byHash.values()];
}

async function listRouteCoverage() {
  const apps = (await callTool('search_applications', { pageSize: 100 })).items || [];
  const out = [];
  for (const app of apps) {
    const base = { name: app.name, appId: app.appID, language: app.language, status: app.status };
    try {
      // get_route_coverage nests its payload under `data`; other tools do not.
      const res = await callTool('get_route_coverage', { appId: app.appID });
      const c = res.data || res;
      out.push({
        ...base,
        totalRoutes: c.totalRoutes,
        exercised: c.exercisedCount,
        discovered: c.discoveredCount,
        coveragePercent: c.coveragePercent,
        vulnerabilities: c.totalVulnerabilities,
        criticalVulnerabilities: c.totalCriticalVulnerabilities,
        routes: (c.routes || []).map((r) => {
          const obs = (r.observations || [])[0] || {};
          return { url: obs.url || '', verb: (obs.verb || '').toUpperCase(), status: r.status, vulnerabilities: r.vulnerabilities };
        }),
      });
    } catch (err) {
      // Route coverage needs an Assess license; show the app rather than failing the page.
      out.push({ ...base, totalRoutes: 0, exercised: 0, discovered: 0, coveragePercent: 0, vulnerabilities: 0, criticalVulnerabilities: 0, routes: [], error: err.message });
    }
  }
  return out;
}

module.exports = { configured, callTool, listVulnerabilities, listLibraries, listRouteCoverage, cveReport, listAttacks, vulnerabilityReport };
