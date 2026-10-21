#!/usr/bin/env node
// One-time setup. Registers this demo server as its own OAuth client on your
// Contrast tenant so it can mint its own access tokens and never expire
// mid-demo.
//
// Why this exists: the MCP endpoint only accepts OAuth Bearer tokens, and the
// token Claude Code holds lasts about 15 minutes. The server cannot refresh
// that one, because this authorization server rotates refresh tokens and doing
// so would invalidate Claude Code's copy and break its MCP connection. Giving
// the server its own client sidesteps that entirely.
//
// Run:  npm run setup
// Undo: delete .contrast-client.json, and revoke the client in Contrast.

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

// The name the official setup command uses:
//   claude mcp add --transport http contrast-hosted-mcp https://<your-host>/mcp
// Override with CONTRAST_MCP_NAME if you registered it under another name.
const SERVER_NAME = process.env.CONTRAST_MCP_NAME || 'contrast-hosted-mcp';
const OUT = path.join(__dirname, '..', '.contrast-client.json');

// Reuse the library's credential chain so this works wherever that does:
// macOS keychain, the Claude Code credentials file, or an explicit token.
function borrowedCredentials() {
  return require('../lib/mcp').credentialSource();
}


async function main() {
  if (fs.existsSync(OUT)) {
    console.log(`Already set up: ${OUT}`);
    console.log('Delete that file and re-run if you want to register again.');
    return;
  }

  const entry = borrowedCredentials();
  const issuer = entry.issuer || new URL(entry.serverUrl).origin;

  const meta = await (await fetch(`${issuer}/.well-known/oauth-authorization-server`)).json();
  if (!meta.registration_endpoint) throw new Error('This authorization server does not advertise dynamic registration.');

  // Registration is itself protected, so authorize it with the access token
  // Claude Code currently holds. This reads that token but never rotates it.
  const reg = await fetch(meta.registration_endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${entry.accessToken}` },
    body: JSON.stringify({
      client_name: 'contrast-mcp-live-reports-demo (local)',
      redirect_uris: ['http://127.0.0.1:5200/callback'],
      grant_types: ['client_credentials'],
      token_endpoint_auth_method: 'client_secret_post',
      scope: 'openid profile',
    }),
  });

  const text = await reg.text();
  if (!reg.ok) {
    if (reg.status === 401) {
      console.error('Registration rejected (401). The token Claude Code holds has probably expired.');
      console.error('Run any Contrast command in Claude Code to refresh it, then re-run: npm run setup');
    } else if (reg.status === 403 && /insufficient_scope/.test(text)) {
      console.error('This tenant will not let you register an OAuth client (403 insufficient_scope).');
      console.error('Your token carries only the "openid profile" scopes, and this authorization');
      console.error('server advertises no scope that permits dynamic client registration, so this');
      console.error('is a tenant policy rather than anything you can fix locally.');
      console.error('');
      console.error('Options, in rough order of effort:');
      console.error('  1. Ask a Contrast admin to pre-create an OAuth client for this tool, then');
      console.error('     put its id and secret in .contrast-client.json yourself. The format is');
      console.error('     { clientId, clientSecret, tokenEndpoint, serverUrl }.');
      console.error('  2. Keep the default. The server borrows the token Claude Code holds, which');
      console.error('     works fine but lapses roughly every 15 minutes.');
    } else {
      console.error(`Registration failed (${reg.status}): ${text.slice(0, 400)}`);
    }
    process.exit(1);
  }

  const client = JSON.parse(text);
  if (!client.client_secret) {
    console.error('The server registered a client but issued no secret, so client_credentials cannot be used.');
    console.error('Response:', JSON.stringify(client).slice(0, 400));
    process.exit(1);
  }

  // Prove it works before saving, so setup never leaves a half-working config.
  const form = new URLSearchParams({
    grant_type: 'client_credentials',
    client_id: client.client_id,
    client_secret: client.client_secret,
    scope: 'openid profile',
  });
  const tokRes = await fetch(meta.token_endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: form,
  });
  if (!tokRes.ok) {
    console.error(`Client registered, but client_credentials was refused (${tokRes.status}):`);
    console.error((await tokRes.text()).slice(0, 400));
    console.error('\nNothing was saved. Tell Claude, and it will fall back to the browser-based flow.');
    process.exit(1);
  }
  const tok = await tokRes.json();

  const probe = await fetch(entry.serverUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json, text/event-stream',
      Authorization: `Bearer ${tok.access_token}`,
    },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'get_user_info', arguments: {} } }),
  });
  if (!probe.ok) {
    console.error(`Got a token, but the MCP server rejected it (${probe.status}).`);
    console.error('A client-credentials token may not carry your user identity on this tenant.');
    console.error('Nothing was saved. Tell Claude, and it will fall back to the browser-based flow.');
    process.exit(1);
  }

  fs.writeFileSync(OUT, JSON.stringify({
    clientId: client.client_id,
    clientSecret: client.client_secret,
    tokenEndpoint: meta.token_endpoint,
    serverUrl: entry.serverUrl,
    registeredAt: new Date().toISOString(),
  }, null, 2), { mode: 0o600 });

  console.log('Done. The server now has its own credentials and refreshes itself.');
  console.log(`  Saved to ${OUT} (gitignored, chmod 600)`);
  console.log(`  Tokens last ${tok.expires_in}s and are renewed automatically, with no Claude Code involvement.`);
  console.log('\nStart the reports with: npm start');
}

main().catch((err) => { console.error(err.message); process.exit(1); });
