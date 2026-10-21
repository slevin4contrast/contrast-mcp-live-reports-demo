// Calls the Contrast MCP server directly. Same tools, same responses the MCP
// returns in chat, so there is no second API client to keep in sync.
//
// Two ways to authenticate, in order of preference:
//
// 1. Own session (.contrast-client.json, written by `npm run login`).
//    The server holds a refresh token of its own and renews access tokens
//    before they lapse. Nothing expires mid-demo and Claude Code is not
//    involved at all.
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

// The name the official setup command uses:
//   claude mcp add --transport http contrast-hosted-mcp https://<your-host>/mcp
// Override with CONTRAST_MCP_NAME if you registered it under another name.
const SERVER_NAME = process.env.CONTRAST_MCP_NAME || 'contrast-hosted-mcp';
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
let inFlight = null;

function saveClient(cfg) {
  fs.writeFileSync(CLIENT_FILE, JSON.stringify(cfg, null, 2), { mode: 0o600 });
}

async function grant(cfg) {
  // This server's own client is registered for authorization_code and
  // refresh_token only, so renewal is a refresh_token grant authenticated with
  // the client secret. client_credentials is supported too, for a client an
  // admin created with that grant.
  const body = cfg.refreshToken
    ? { grant_type: 'refresh_token', refresh_token: cfg.refreshToken, client_id: cfg.clientId }
    : { grant_type: 'client_credentials', client_id: cfg.clientId, scope: cfg.scope || 'openid profile' };

  const headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
  if (cfg.clientSecret) {
    headers.Authorization = 'Basic ' + Buffer.from(`${cfg.clientId}:${cfg.clientSecret}`).toString('base64');
  }

  const res = await fetch(cfg.tokenEndpoint, {
    method: 'POST',
    headers,
    body: new URLSearchParams(body),
  });
  if (!res.ok) {
    throw new Error(`Could not renew the Contrast session (${res.status}). Run npm run login again, or delete .contrast-client.json to fall back to the Claude Code token.`);
  }
  const tok = await res.json();

  // This server rotates refresh tokens, so persist the new one or the next
  // renewal fails. Only ever written to our own file, never to the keychain.
  if (tok.refresh_token && tok.refresh_token !== cfg.refreshToken) {
    saveClient({ ...cfg, refreshToken: tok.refresh_token, renewedAt: new Date().toISOString() });
  }

  minted = {
    token: tok.access_token,
    expiresAt: Date.now() + Math.max(30, (tok.expires_in || 900) - 60) * 1000,
  };
  return minted.token;
}

async function mintToken(cfg) {
  if (minted.token && Date.now() < minted.expiresAt) return minted.token;
  // Collapse concurrent renewals. Two parallel refresh_token grants would make
  // the loser's token invalid, since the server rotates on every use.
  if (!inFlight) inFlight = grant(cfg).finally(() => { inFlight = null; });
  return inFlight;
}

function credentials() {
  const raw = execFileSync('security', ['find-generic-password', '-s', 'Claude Code-credentials', '-w'], { encoding: 'utf8' });
  const entry = Object.values(JSON.parse(raw).mcpOAuth || {}).find((e) => e.serverName === SERVER_NAME);
  if (!entry) {
    throw new Error(`No stored credentials for "${SERVER_NAME}". Connect the MCP server first:\n`
      + `  claude mcp add --transport http ${SERVER_NAME} https://<your-contrast-host>/mcp\n`
      + 'then run a Contrast command so it signs in. If you registered it under a different name, '
      + 'set CONTRAST_MCP_NAME to match.');
  }
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

// Every tool call is recorded so the pages can show what the MCP actually did:
// which tools ran, with what arguments, how long each took and how much came
// back. Seeing search_cves -> 1.8s -> 25 results is the point of the demo.
let trace = null;

function beginTrace() {
  trace = [];
  return trace;
}

function endTrace() {
  const t = trace || [];
  trace = null;
  return t;
}

function countRows(payload) {
  if (!payload || typeof payload !== 'object') return null;
  if (Array.isArray(payload.items)) return payload.items.length;
  const data = payload.data;
  if (data && Array.isArray(data.routes)) return data.routes.length;
  if (data && Array.isArray(data.apps)) return data.apps.length;
  return null;
}

// Indirection so tests can simulate an organization far larger than any demo
// one. Production always uses the real implementation below.
let callToolImpl = null;

function callTool(name, args = {}) {
  return (callToolImpl || realCallTool)(name, args);
}

function __setCallTool(fn) {
  callToolImpl = fn;
}

async function realCallTool(name, args = {}) {
  const startedAt = Date.now();
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
      throw new Error('Contrast rejected the token. Retrying will renew it; if that keeps happening, run npm run login again.');
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
  const parsed = JSON.parse(text);

  if (trace) {
    trace.push({
      tool: name,
      args,
      ms: Date.now() - startedAt,
      rows: countRows(parsed),
      totalItems: parsed.totalItems ?? parsed.data?.totalRoutes ?? null,
      bytes: text.length,
    });
  }
  return parsed;
}

// allStatuses includes remediated and closed findings, which the tool leaves out
// by default. Needed for anything that measures remediation.
// Page until the source is exhausted. This used to stop after 20 pages, so an
// organization with more than 1,000 findings silently reported 1,000, which is
// exactly the kind of quietly wrong number this project exists to expose. There
// is still a ceiling, because an unbounded loop against a huge org would hang
// the page, but reaching it is reported rather than hidden.
const MAX_ITEMS = Number(process.env.CONTRAST_MAX_ITEMS || 25000);

async function pageThrough(tool, baseArgs, pageSize, mapItem) {
  const items = [];
  let truncated = false;
  for (let page = 1; ; page++) {
    const res = await callTool(tool, { ...baseArgs, page, pageSize });
    const batch = res.items || [];
    items.push(...batch.map(mapItem));
    if (items.length >= MAX_ITEMS) { truncated = true; break; }
    if (!res.hasMorePages || !batch.length) break;
  }
  return { items, truncated, limit: MAX_ITEMS };
}

// Run a job per application, a few at a time. These used to run strictly one
// after another, so 200 applications meant minutes of waiting. The limit stops
// us opening 200 sockets at once and being rate limited.
const FANOUT = Number(process.env.CONTRAST_CONCURRENCY || 6);

async function mapWithLimit(items, limit, job) {
  const out = new Array(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) || 0 }, async () => {
    for (;;) {
      const i = next++;
      if (i >= items.length) return;
      out[i] = await job(items[i], i);
    }
  });
  await Promise.all(workers);
  return out;
}

async function listVulnerabilities({ allStatuses = false } = {}) {
  const statuses = 'Reported,Suspicious,Confirmed,NotAProblem,Remediated,Fixed,AutoRemediated';
  return pageThrough('search_vulnerabilities', allStatuses ? { statuses } : {}, 50, (v) => ({
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
  }));
}

// One vulnerability in full, plus the list for the picker. With no id it picks
// the most severe finding, since that is what a demo wants to open on.
const SEV_RANK = { Critical: 0, High: 1, Medium: 2, Low: 3, Note: 4 };

async function vulnerabilityReport(vulnId, appId) {
  const list = (await listVulnerabilities()).items.sort(
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

  // Fetch each application's libraries concurrently, then merge. Merging after
  // the fan-out keeps the shared map free of interleaved writes.
  const perApp = await mapWithLimit(apps, FANOUT, async (app) => {
    const rows = [];
    for (let page = 1; page <= 40; page++) {
      const res = await callTool('list_application_libraries', { appId: app.appID, page, pageSize: 50 });
      rows.push(...(res.items || []));
      if (!res.hasMorePages || !(res.items || []).length) break;
    }
    return { app, rows };
  });

  const byHash = new Map();
  for (const { app, rows } of perApp) {
    {
      for (const l of rows) {
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
    }
  }
  return [...byHash.values()];
}

async function listRouteCoverage() {
  const apps = (await callTool('search_applications', { pageSize: 100 })).items || [];
  return mapWithLimit(apps, FANOUT, async (app) => {
    const base = { name: app.name, appId: app.appID, language: app.language, status: app.status };
    try {
      // get_route_coverage nests its payload under `data`; other tools do not.
      const res = await callTool('get_route_coverage', { appId: app.appID });
      const c = res.data || res;
      return {
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
      };
    } catch (err) {
      // Route coverage needs an Assess license; show the app rather than failing the page.
      return { ...base, totalRoutes: 0, exercised: 0, discovered: 0, coveragePercent: 0, vulnerabilities: 0, criticalVulnerabilities: 0, routes: [], error: err.message };
    }
  });
}

// The catalogue the MCP server advertises. This is what a coding agent sees
// when it connects, so showing it verbatim is the clearest answer to "what can
// this actually do for me".
async function listTools() {
  const startedAt = Date.now();
  const { accessToken, serverUrl } = await auth();
  const res = await fetch(serverUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json, text/event-stream',
      Authorization: `Bearer ${accessToken}`,
    },
    body: JSON.stringify({ jsonrpc: '2.0', id: ++id, method: 'tools/list', params: {} }),
  });
  if (res.status === 401) throw new Error('Contrast MCP token expired. Run /mcp in Claude Code to reauthorize.');
  if (!res.ok) throw new Error(`Contrast MCP returned ${res.status} for tools/list`);

  const text = await res.text();
  const payload = res.headers.get('content-type')?.includes('event-stream')
    ? JSON.parse(text.split('\n').filter((l) => l.startsWith('data:')).pop().slice(5))
    : JSON.parse(text);
  if (payload.error) throw new Error(payload.error.message);

  const tools = (payload.result?.tools || []).map((t) => ({
    name: t.name,
    description: t.description || '',
    schema: t.inputSchema || {},
  }));

  // tools/list is an MCP call like any other, so the inspector should show it.
  if (trace) {
    trace.push({ tool: 'tools/list', args: {}, ms: Date.now() - startedAt, rows: tools.length, totalItems: tools.length, bytes: text.length });
  }
  return tools;
}

// Sample data for MOCK mode, so the demo runs with no Contrast session at all.
// Regenerate with: npm run fixtures
function loadFixture(name) {
  const file = path.join(__dirname, '..', 'fixtures', `${name}.json`);
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (err) {
    throw new Error(`Missing or unreadable fixture "${name}" (${file}). Run npm run fixtures against a live org.`);
  }
}

module.exports = { configured, callTool, __setCallTool, loadFixture, beginTrace, endTrace, listTools, listVulnerabilities, listLibraries, listRouteCoverage, cveReport, listAttacks, vulnerabilityReport };
