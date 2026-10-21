#!/usr/bin/env node
// One-time login that gives this server its own Contrast session.
//
// Why: the MCP endpoint only accepts OAuth bearer tokens, and the token Claude
// Code holds lasts about 15 minutes. The server cannot refresh that one,
// because this authorization server rotates refresh tokens and doing so would
// invalidate Claude Code's copy and break its MCP connection.
//
// So this does two things, once:
//   1. Registers an OAuth client of its own (secret never expires).
//   2. Signs you in through the browser to obtain a refresh token for it.
// From then on the server renews its own access tokens indefinitely, on a token
// chain entirely separate from Claude Code's.
//
// Run:  npm run login
// Undo: delete .contrast-client.json, and revoke "contrast-reports-local" in Contrast.

const fs = require('fs');
const http = require('http');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');

// The name the official setup command uses:
//   claude mcp add --transport http contrast-hosted-mcp https://<your-host>/mcp
// Override with CONTRAST_MCP_NAME if you registered it under another name.
const SERVER_NAME = process.env.CONTRAST_MCP_NAME || 'contrast-hosted-mcp';
const OUT = path.join(__dirname, '..', '.contrast-client.json');
const PORT = Number(process.env.LOGIN_PORT || 5200);
const REDIRECT = `http://127.0.0.1:${PORT}/callback`;
const TIMEOUT_MIN = Number(process.env.LOGIN_TIMEOUT_MIN || 10);

const b64url = (b) => b.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const basic = (id, secret) => 'Basic ' + Buffer.from(`${id}:${secret}`).toString('base64');
const save = (cfg) => fs.writeFileSync(OUT, JSON.stringify(cfg, null, 2), { mode: 0o600 });
const load = () => { try { return JSON.parse(fs.readFileSync(OUT, 'utf8')); } catch { return null; } };

function keychainEntry() {
  const raw = execFileSync('security', ['find-generic-password', '-s', 'Claude Code-credentials', '-w'], { encoding: 'utf8' });
  const entry = Object.values(JSON.parse(raw).mcpOAuth || {}).find((e) => e.serverName === SERVER_NAME);
  if (!entry) {
    throw new Error(`No stored credentials for "${SERVER_NAME}". Connect the MCP server first:\n`
      + `  claude mcp add --transport http ${SERVER_NAME} https://<your-contrast-host>/mcp\n`
      + 'then run a Contrast command so it signs in. Set CONTRAST_MCP_NAME if you used another name.');
  }
  return entry;
}

// Registration is protected, so it borrows Claude Code's current access token
// once. It reads that token and never rotates it.
async function registerClient(issuer, accessToken) {
  const res = await fetch(`${issuer}/oauth2/client/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${accessToken}` },
    body: JSON.stringify({
      client_name: 'contrast-reports-local',
      redirect_uris: [REDIRECT],
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      scope: 'openid profile',
    }),
  });
  const text = await res.text();
  if (!res.ok) {
    if (res.status === 401) {
      throw new Error('Registration rejected (401). Claude Code\'s token has probably lapsed.\nRun any Contrast command in Claude Code, then try again.');
    }
    throw new Error(`Could not register a client (${res.status}): ${text.slice(0, 300)}`);
  }
  const c = JSON.parse(text);
  if (!c.client_id || !c.client_secret) throw new Error('Registration returned no usable credentials.');
  return c;
}

function waitForCode(expectedState) {
  return new Promise((resolve, reject) => {
    const page = (title, body, colour) => `<!doctype html><meta charset="utf-8"><title>${title}</title>
      <body style="font-family:system-ui;background:#0a0e27;color:#fff;display:grid;place-items:center;height:100vh;margin:0;text-align:center">
      <div><h1 style="color:${colour}">${title}</h1><p style="opacity:.8">${body}</p></div>`;

    const server = http.createServer((req, res) => {
      const url = new URL(req.url, `http://127.0.0.1:${PORT}`);
      if (url.pathname !== '/callback') { res.writeHead(404); return res.end(); }
      const code = url.searchParams.get('code');
      const err = url.searchParams.get('error');

      if (err || !code || url.searchParams.get('state') !== expectedState) {
        res.writeHead(400, { 'Content-Type': 'text/html' });
        res.end(page('Login failed', err || 'Missing code, or state did not match.', '#ff4444'));
        server.close();
        return reject(new Error(`Authorization failed: ${err || 'bad callback'}`));
      }
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(page('Signed in', 'You can close this tab and return to the terminal.', '#00c878'));
      server.close();
      resolve(code);
    });

    server.on('error', (e) => reject(e.code === 'EADDRINUSE'
      ? new Error(`Port ${PORT} is busy. Free it, or run: LOGIN_PORT=5300 npm run login`)
      : e));
    server.listen(PORT, '127.0.0.1');
    setTimeout(() => {
      server.close();
      reject(new Error(`Timed out after ${TIMEOUT_MIN} minutes. Nothing was saved; run npm run login again when ready.`));
    }, TIMEOUT_MIN * 60000);
  });
}

async function main() {
  const existing = load();
  if (existing && existing.refreshToken) {
    console.log(`Already signed in: ${OUT}`);
    console.log('Delete that file and run again to start over.');
    return;
  }

  const entry = keychainEntry();
  const issuer = entry.issuer || new URL(entry.serverUrl).origin;
  const meta = await (await fetch(`${issuer}/.well-known/oauth-authorization-server`)).json();

  // Reuse a client from a previous half-finished run rather than piling up registrations.
  let client = existing && existing.clientId && existing.clientSecret
    ? { client_id: existing.clientId, client_secret: existing.clientSecret }
    : null;

  if (!client) {
    console.log('Registering an OAuth client for this server...');
    client = await registerClient(issuer, entry.accessToken);
    save({ clientId: client.client_id, clientSecret: client.client_secret,
           tokenEndpoint: meta.token_endpoint, serverUrl: entry.serverUrl, scope: 'openid profile' });
    console.log('  Registered. Its secret does not expire.\n');
  }

  const verifier = b64url(crypto.randomBytes(32));
  const challenge = b64url(crypto.createHash('sha256').update(verifier).digest());
  const state = b64url(crypto.randomBytes(16));

  const authUrl = `${meta.authorization_endpoint}?` + new URLSearchParams({
    response_type: 'code',
    client_id: client.client_id,
    redirect_uri: REDIRECT,
    scope: 'openid profile',
    state,
    code_challenge: challenge,
    code_challenge_method: 'S256',
  });

  console.log(`Opening your browser to sign in. You have ${TIMEOUT_MIN} minutes.`);
  console.log(`If it does not open, visit:\n${authUrl}\n`);

  const codePromise = waitForCode(state);
  try { execFileSync('open', [authUrl]); } catch { /* the printed link still works */ }
  const code = await codePromise;

  const tokRes = await fetch(meta.token_endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Authorization: basic(client.client_id, client.client_secret),
    },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: REDIRECT,
      client_id: client.client_id,
      code_verifier: verifier,
    }),
  });
  if (!tokRes.ok) throw new Error(`Token exchange failed (${tokRes.status}): ${(await tokRes.text()).slice(0, 300)}`);
  const tok = await tokRes.json();
  if (!tok.refresh_token) throw new Error('No refresh token was issued, so the server cannot stay signed in.');

  // Prove the token actually works against the MCP server before saving it.
  const probe = await fetch(entry.serverUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json, text/event-stream',
      Authorization: `Bearer ${tok.access_token}`,
    },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'get_user_info', arguments: {} } }),
  });
  if (!probe.ok) throw new Error(`Signed in, but the MCP server rejected the token (${probe.status}). Nothing saved.`);

  save({
    clientId: client.client_id,
    clientSecret: client.client_secret,
    refreshToken: tok.refresh_token,
    tokenEndpoint: meta.token_endpoint,
    serverUrl: entry.serverUrl,
    scope: 'openid profile',
    signedInAt: new Date().toISOString(),
  });

  console.log('\nDone. The server has its own session and keeps itself signed in.');
  console.log(`  Saved to ${OUT} (gitignored, chmod 600)`);
  console.log(`  Access tokens last ${tok.expires_in}s and renew automatically.`);
  console.log('  Claude Code is no longer involved, and its connection is untouched.\n');
  console.log('Restart the reports with: npm start');
}

main().catch((err) => { console.error('\n' + err.message); process.exit(1); });
