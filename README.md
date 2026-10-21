# Contrast MCP Live Reports

An MCP server is a set of tools an AI assistant can call on your behalf. The Contrast MCP server
exposes 27 of them, covering vulnerabilities, third-party libraries, CVE exposure, live attacks,
route coverage and application inventory.

These pages make that concrete. Each one is an ordinary web page that calls those same tools
directly and draws the answer, and each shows which tools it called to get there.

**No AI tokens are spent viewing these pages.** MCP is a protocol, not a model. The pages talk to
Contrast over HTTPS and no model runs, so refreshing a dashboard costs nothing in Claude usage.

## Prerequisites

- **Node.js 18 or newer.** Check with `node --version`. Nothing else is installed; this project
  has no dependencies.
- **A Contrast account** with access to at least one organization.
- **An MCP client**, to connect the server and to sign this project in the first time. Claude
  Code, Claude Desktop, Codex CLI, GitHub Copilot CLI and opencode all work. If you use something
  else, see *Using this without Claude* below.
- **A browser**, for the one-time OAuth sign-in.
- macOS, Linux or Windows.

## Before anything else: connect the MCP server

This project reads from the Contrast MCP server, so that has to exist first. Setup and the
supported clients are documented at
[Contrast-Security-OSS/mcp-contrast](https://github.com/Contrast-Security-OSS/mcp-contrast#hosted-mcp-server-recommended).
The short version for Contrast SaaS:

```bash
claude mcp add --transport http contrast-hosted-mcp https://app.contrastsecurity.com/mcp
```

Replace the host if you are on a dedicated instance, following `https://<your-contrast-host>/mcp`.
There is no API key. Authentication is OAuth with PKCE, and your first tool call opens a browser
to sign in with your existing Contrast credentials and pick an organization.

Then confirm it works by asking your assistant something like *"use Contrast to list my
applications"*. If that returns data, this project will too.

Two things to know:

- **The name matters.** These scripts look for an MCP connection called `contrast-hosted-mcp`,
  which is what the command above creates. If you registered it under another name, set
  `CONTRAST_MCP_NAME` to match.
- **On-premises or EOP?** The hosted server is SaaS only. There is a local Docker server that
  authenticates with API and service keys instead; see the same repo. This project has only been
  tested against the hosted one.

## Quick start

```bash
npm start
```

Then open http://localhost:3000. There is no API key to configure here either.

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

### What each page needs from Contrast

Pages only show what your licences and agents actually report. If one looks empty, this is
usually why rather than a fault:

| Page | Needs |
|---|---|
| Vulnerability dashboard, PoC generator, SmartFix guide, Compliance | Assess, with agents reporting |
| Route coverage | Assess, per application; applications without it are listed with zero routes |
| Library security | Library data from the agent, which comes with Assess |
| Attack activity | ADR, and attacks actually observed |
| CVE impact | CVE Shield data |

When a page has nothing to show it says so, and lists what to check, rather than rendering
blank. `npm run test:empty` proves that by serving every data source empty and asserting each
page explains itself.

`compliance_mttr.html` is only partly live. Its KPIs, SLA table and finding ages come from the
org, but the NIST, PCI-DSS, OWASP and SOC 2 sections below them are sample content. Contrast does
not store control mappings, and the demo org has no remediation history, so MTTR is reported as
not available rather than invented. A banner marks where the live data stops.

## Using this without Claude

Nothing here calls a language model, so your choice of assistant does not matter at runtime. MCP
is a vendor-neutral protocol, and these pages are an ordinary web app calling that endpoint over
HTTPS.

The one place Claude appears is the initial sign-in: `npm run login` reads the token Claude Code
already stored, so it can register an OAuth client of its own. After that the server renews
itself and Claude Code is never consulted again, which you can verify by disconnecting it.

Contrast's hosted MCP server also works with Codex CLI, GitHub Copilot CLI, opencode and Claude
Desktop. Those store credentials elsewhere, so supply a token from whichever you use:

```bash
export CONTRAST_MCP_URL=https://<your-contrast-host>/mcp
export CONTRAST_ACCESS_TOKEN=<an access token>
npm run login
```

Credentials are looked for in that order: these variables, then the macOS keychain, then Claude
Code's credentials file, which is where it keeps them on Linux and Windows.

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
npm test              # unit tests, then 94 browser and API checks
npm run test:unit     # just the unit tests, under a second
npm run test:empty    # every source empty: does each page explain itself?
npm run test:scale    # a synthetic 200-application org: does the DOM stay sane?
npm test -- --no-ui   # skip the browser checks
```

No dependencies. The smoke suite runs in mock mode, so it needs no Contrast session and works
offline. The unit tests stub the MCP client to simulate organizations no demo tenant can provide:
60,000 findings, 40 applications, and an application whose licence does not cover route
coverage. It covers
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

## On a large organization

Paging runs until the source is exhausted, with a ceiling of 25,000 items per endpoint. If an
organization exceeds that the page says so, rather than quietly showing a partial count. Raise it
with `CONTRAST_MAX_ITEMS`.

Route coverage and library security cover every application, fetching six at a time; tune with
`CONTRAST_CONCURRENCY`. On eight applications they take under two seconds. On several hundred
expect tens of seconds, and the page counts the wait out loud so it does not look hung.

Every long list is paged rather than drawn in full, and everything is reachable:

| List | Shows first | Then |
|---|---|---|
| Libraries with CVEs | 100 | Show more, plus filters |
| Applications in route coverage | 50 | Show more |
| Findings per severity | 50 critical and high, 24 medium, 12 low and note | Show more per section |
| CVEs | the 25 highest scoring | Show more |
| Oldest open findings | 15 | heading says how many are open |
| Finding pickers | 500 options | type to filter by title, app or rule |

Changing a filter resets the window, so a stale page of results cannot leak through.

`npm run test:scale` checks this. It generates a synthetic organization of 2,000 libraries,
5,000 findings and 200 applications, serves it through mock mode, and fails if any page draws
more DOM than its budget. Uncapped, library security drew 27,000 elements and 3 MB; it now draws
about 7,000 and under 1 MB.

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
