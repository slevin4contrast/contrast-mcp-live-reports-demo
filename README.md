# Contrast MCP Live Reports

An MCP server is a set of tools an AI assistant can call on your behalf. The Contrast MCP server
exposes 27 of them, covering vulnerabilities, third-party libraries, CVE exposure, live attacks,
route coverage and application inventory.

These pages make that concrete. Each one is an ordinary web page that calls those same tools
directly and draws the answer, and each shows which tools it called to get there.

**No AI tokens are spent viewing these pages.** MCP is a protocol, not a model. The pages talk to
Contrast over HTTPS and no model runs, so refreshing a dashboard costs nothing in Claude usage.

## Quick start

```bash
npm start
```

Then open http://localhost:3000. There is no API key to configure.

With no Contrast session the server runs in mock mode and serves sample data from `fixtures/`,
labelled on the page with the date it was captured.

## Start here

`tool_explorer.html` lists every tool the server exposes, read from the server itself through
`tools/list` rather than written by hand, grouped by the question you are trying to answer. The
read-only ones can be run against your own organization so you can see the shape of the answer.

## Seeing the MCP calls

Every report page carries a collapsible panel showing the calls behind it: which tools ran, with
what arguments, how long each took and how many rows came back. Opening the CVE page shows four
calls in about two seconds, starting with `search_cves` returning 25 rows.

## Live pages

| Page | Endpoint | MCP tools |
|---|---|---|
| `tool_explorer.html` | `/api/tools`, `/api/tool` | `tools/list`, plus any read-only tool you run |
| `vulnerability_dashboard.html` | `/api/vulnerabilities` | `search_vulnerabilities` |
| `route_coverage.html` | `/api/routes` | `search_applications`, `get_route_coverage` |
| `library_security.html` | `/api/libraries` | `search_applications`, `list_application_libraries` |
| `cve_impact.html` | `/api/cves` | `search_cves`, `get_cve_impact`, `list_cve_issues`, `list_applications_by_cve` |
| `attack_activity.html` | `/api/attacks` | `search_attacks` |
| `compliance_mttr.html` | `/api/compliance` | `search_vulnerabilities` (all statuses) |
| `poc_generator.html` | `/api/vulnerability` | `search_vulnerabilities`, `get_vulnerability` |
| `smartfix_guide.html` | `/api/vulnerability` | `search_vulnerabilities`, `get_vulnerability` |

`/api/cves` takes an optional `?id=CVE-YYYY-NNNN`, and `/api/vulnerability` takes `?id=` and
`?appId=`. With no id each opens on the most significant finding.

`compliance_mttr.html` is only partly live. Its KPIs, SLA table and finding ages come from the
org, but the NIST, PCI-DSS, OWASP and SOC 2 sections below them are sample content. Contrast does
not store control mappings, and the demo org has no remediation history, so MTTR is reported as
not available rather than invented. A banner marks where the live data stops.

## Keeping it signed in

The MCP endpoint only accepts OAuth bearer tokens. By default the server borrows the one Claude
Code holds, which lasts about 15 minutes, so a long demo needs a Claude Code command now and then
to renew it.

Run this once and that goes away:

```bash
npm run login
```

It registers an OAuth client of its own, opens a browser for you to sign in, and keeps the
resulting refresh token in `.contrast-client.json` (gitignored, chmod 600). After that the server
renews its own access tokens indefinitely on a token chain separate from Claude Code's, so
neither can disturb the other.

To undo it, delete `.contrast-client.json` and revoke the `contrast-reports-local` client in
Contrast. The server falls back to borrowing Claude Code's token.

`npm run setup` is an alternative that registers a client with the `client_credentials` grant and
needs no browser. It requires a tenant that permits dynamic client registration; on the eval
tenant it answers 403 `insufficient_scope`, so use `npm run login` there.

## When something fails

Each page says what actually broke rather than guessing:

- **Contrast session expired.** The server is running, it just has no valid token. Renew it, or
  run `npm run login` so it stops happening.
- **Cannot reach the local server.** Start it with `npm start`.
- **Something else is on port 3000.** The API returned a web page instead of data.
- **Hosted copy, so no live data.** You are on GitHub Pages, which cannot reach Contrast.

## Tests

```bash
npm test              # 74 checks, about 17 seconds
npm test -- --no-ui   # skip the browser checks, about 5 seconds
```

No dependencies. Runs in mock mode, so it needs no Contrast session and works offline. It covers
every endpoint's shape, the file server's refusal to serve anything but pages, inline script
syntax, that no credentials are committed, that each snapshot carries real captured data, and
that every page renders to a terminal state in headless Chrome.

The suite exists because mock mode was silently broken for hours: `loadFixture` had been dropped
in a refactor and every endpoint returned 502. The first run caught it.

## Captured data

Two kinds, both regenerable, both dated so they cannot quietly drift:

```bash
npm run fixtures    # sample data for mock mode
npm run snapshot    # frozen _static pages, server must be running live
```

A `_static` page is the real page with a real API response frozen into it. The shared module
notices the frozen payload, serves it instead of fetching, and labels the page with its capture
date. They open with no server and no network.

### On GitHub Pages

The repo publishes as a static site. Pages cannot reach Contrast, so the hosted copy serves the
`_static` snapshots and says so. The index rewrites its own links and relabels the badges when it
detects it is not on localhost.

## Still static

`pr_security_gate.html`, `attack_response_playbook.html` and `developer_training.html` are
unconverted snapshots, mostly written guidance rather than data. `prompts.html` documents the
prompts behind each report.

## Layout

```
server.js               Local server and API routes, no dependencies
lib/mcp.js              Contrast MCP client, the only file that talks to the server
assets/reports.js       Shared page behaviour: fetching, badges, errors, the MCP panel
scripts/login.js        One-time browser sign-in for self-renewing credentials
scripts/register-client.js  Alternative sign-in where the tenant allows client registration
scripts/fixtures.js     Regenerates fixtures/ from a live org
scripts/snapshot.js     Regenerates the _static pages from live data
test/smoke.js           The suite npm test runs
fixtures/               Sample data for mock mode
*_static.html           Frozen captures of the live pages
```

## Adding another live page

Add a function to `lib/mcp.js` that calls the tool you need through `callTool`, add a route to the
`routes` map in `server.js`, then have the page fetch it. Load `assets/reports.js` and the badge,
timestamp, error handling, MCP panel and frozen-snapshot support come with it.

Two quirks worth knowing. `get_route_coverage` and `list_applications_by_cve` nest their payload
under a `data` key, while the other tools return fields at the top level. And since pages build
HTML in template literals, a syntax error leaves the page silently stuck on "Loading"; `npm test`
catches that.

## Notes

This runs on localhost against a session tied to your own Contrast account, so it shows whatever
that account can see. Before running it anywhere other than a local machine, get IT and security
approval.

`fixtures/` holds real data from the demo org. If you point this at a different organization,
consider whether its exported findings, routes and library inventory belong in a public repo.

## Origin

Started from [Contrast-Security-OSS/contrast-generated-reports](https://github.com/Contrast-Security-OSS/contrast-generated-reports),
where every page was a static snapshot with hand-written numbers. Converting them to live data
showed how far those had drifted: 24 findings against an actual 27, 60.77% route coverage against
46%, 127 libraries against 420.
