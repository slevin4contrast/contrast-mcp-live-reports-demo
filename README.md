# Contrast MCP Demo Reports

Security reports generated from the Contrast MCP server. Some pages are static snapshots.
Others are live and fetch data when you open them.

## Quick start

```bash
npm start        # or: node server.js
```

Then open http://localhost:3000.

That is the whole setup. There is no API key to configure.

## How the live pages work

The live pages call a small local server, which calls the Contrast MCP server at
`https://eval.contrastsecurity.com/mcp` using the same tools Claude Code calls, such as
`search_vulnerabilities` and `get_route_coverage`. There is no second API client and no
separate set of credentials to manage.

Authentication reuses the OAuth token Claude Code already stored in the macOS keychain when
you connected the MCP server. The server reads that token per request, so a refreshed token is
picked up automatically. The token never reaches the browser.

### Making it refresh itself (recommended for demos)

By default the server borrows the OAuth token Claude Code holds, and that token lasts about 15
minutes. Renewing it means running something in Claude Code, which is fine while you are working
but a nuisance during a long demo.

Run this once and the problem goes away:

```bash
npm run setup
```

That registers this server as its own OAuth client on your Contrast tenant and saves the
credentials to `.contrast-client.json`, which is gitignored and written chmod 600. From then on
the server mints its own access tokens and renews them a minute before they lapse, so nothing
expires mid-demo and Claude Code is never involved.

It is deliberately safe in both directions. The server never touches Claude Code's refresh token,
so it cannot break your MCP connection, and Claude Code cannot invalidate the server's
credentials. To undo it, delete `.contrast-client.json` and revoke the client in Contrast; the
server falls back to borrowing Claude Code's token.

Setup reads Claude Code's current access token once to authorize the registration, so the MCP
server needs to be connected and the token valid when you run it. If it reports a 401, run any
Contrast command in Claude Code and try again.

**This may not be available to you.** On the eval tenant the registration endpoint answers 403
`insufficient_scope`, because user tokens carry only `openid profile` and the authorization
server advertises no scope that permits dynamic registration. That is tenant policy, not
something to fix locally. If you hit it, either ask a Contrast admin to pre-create an OAuth
client and write `.contrast-client.json` by hand as
`{ clientId, clientSecret, tokenEndpoint, serverUrl }`, or stay on the default and accept the
15-minute token.

### When a page says the session expired

Access tokens last about 15 minutes, and this server deliberately does not refresh them (see
below). When one lapses, every live page says so and tells you to refresh it from Claude Code.
The server is still running at that point; it just has no valid token. Running any Contrast
command in Claude Code renews the token in the keychain, and the next Refresh picks it up. No
restart needed.

Access tokens last about 15 minutes. Claude Code refreshes them whenever it uses the MCP
server, and this server re-reads the keychain on every request, so the token stays current as
long as you are also using the MCP in Claude Code, which is usually the case during a demo. If
the token has expired, the page shows a message telling you to run `/mcp` in Claude Code to
reauthorize. If no token is found at all, the server starts in mock mode and serves sample data
from `fixtures/`, clearly labeled on the page.

This server deliberately does not refresh the token itself. The authorization server rotates
refresh tokens, so refreshing from here would invalidate the one Claude Code holds and break
its MCP connection until you reconnect.

Every live page carries a badge reading either LIVE or MOCK DATA, a last-refreshed timestamp,
and a Refresh button, so a demo never silently shows stale numbers. Set `MOCK=1` to force
sample data even when a token is available.

## Live pages

| Page | Endpoint | MCP tools |
|---|---|---|
| `vulnerability_dashboard.html` | `/api/vulnerabilities` | `search_vulnerabilities` |
| `route_coverage.html` | `/api/routes` | `search_applications`, `get_route_coverage` |
| `library_security.html` | `/api/libraries` | `search_applications`, `list_application_libraries` |
| `cve_impact.html` | `/api/cves` | `search_cves`, `get_cve_impact`, `list_cve_issues`, `list_applications_by_cve` |
| `attack_map.html` | `/api/attacks` | `search_attacks` |
| `compliance_mttr.html` | `/api/compliance` | `search_vulnerabilities` (all statuses) |
| `poc_generator.html` | `/api/vulnerability` | `search_vulnerabilities`, `get_vulnerability` |
| `smartfix_guide.html` | `/api/vulnerability` | `search_vulnerabilities`, `get_vulnerability` |

`/api/vulnerability` takes an optional `?id=` and `?appId=`, since `get_vulnerability` needs
both. With no id it opens on the most severe finding. The PoC page turns the captured request
into a runnable curl command; Contrast redacts sensitive values first, so placeholders appear
where real data was sent.

`/api/cves` takes an optional `?id=CVE-YYYY-NNNN`. With no id it picks the highest-scoring CVE
that agents have actually seen exploited. The page drives that through a dropdown and a
clickable table.

`compliance_mttr.html` is only partly live. Its KPIs, SLA table and finding ages come from the
org, but the NIST, PCI-DSS, OWASP and SOC 2 sections below them are sample content. Contrast
does not store control mappings, and this org has no remediation history, so MTTR is reported
as not available rather than invented. A banner on the page marks where the live data stops.

### Viewing it on GitHub Pages

The repo is also published as a static site. GitHub Pages cannot reach a Contrast organization,
so the hosted copy serves the `_static` snapshots instead and says so on every page. The index
rewrites its own links and relabels the badges when it detects it is not running on localhost.
To see the reports pull live data, clone the repo and run it locally.

Each live page keeps its original static version next to it, named with a `_static` suffix.
Those open directly in a browser with no server running, which makes them a safe fallback for a
demo with no network.

## Static pages

`poc_generator.html`, `smartfix_guide.html`, `pr_security_gate.html`, `attack_response_playbook.html` and
`developer_training.html` are snapshots. `prompts.html` documents the prompts behind each report.

## Layout

```
server.js                 Local server and API routes, no dependencies
lib/mcp.js                Contrast MCP client, the only file that talks to the server
scripts/register-client.js  One-time setup for self-refreshing credentials
fixtures/                 Sample data used when no token is available
*_static.html             Frozen snapshots of pages that are now live
```

## Adding another live page

Add a function to `lib/mcp.js` that calls the MCP tool you need through `callTool`, add a route
to the `routes` map in `server.js`, then have the page fetch it. The tool names and response
shapes are the ones the MCP server returns in chat, so you can try a tool there first and build
against exactly what you see.

Two quirks worth knowing. `get_route_coverage` and `list_applications_by_cve` nest their
payload under a `data` key, while the other tools return their fields at the top level. And
since the pages build HTML in template literals, syntax-check a page's inline script before
trusting a render, because a parse error leaves the page silently stuck on Loading with no
error in the banner:

```bash
sed -n '/^    <script>$/,/^    <\/script>$/p' page.html | sed '1d;$d' | node --check /dev/stdin
```

## Notes

This runs on localhost and relies on a token tied to your own Contrast account, so it shows
whatever your account can see. Before running it anywhere other than a local machine, get IT
and security approval.

## Origin

Started from [Contrast-Security-OSS/contrast-generated-reports](https://github.com/Contrast-Security-OSS/contrast-generated-reports),
where every page was a static snapshot. This version adds the local server and converts six of
those pages to pull live data through the Contrast MCP server. The original snapshots are kept
beside each live page with a `_static` suffix.
