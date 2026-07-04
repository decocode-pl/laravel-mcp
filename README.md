# decocode/laravel-mcp

Read-only **MCP server** for Laravel applications — safe production data diagnostics for Claude
(claude.ai + Claude Code). Built on the official [`laravel/mcp`](https://laravel.com/docs/mcp).

## Requirements

- PHP `^8.2`
- Laravel `^11.45 | ^12 | ^13` (Laravel 10 must be upgraded first)
- Laravel Passport (OAuth guard for claude.ai custom connectors)

## Infrastructure — three MySQL accounts (per project)

Read-only is enforced at the **database** level, not just in code.

| Account | Grants | Scope | When |
|---|---|---|---|
| `mcp_ctl` | SELECT, INSERT, UPDATE, DELETE | only `mcp_*`, `oauth_*`, `mcp_audit_log` | now |
| `mcp_ro` | **SELECT** | business tables minus blocklist | now |
| `mcp_rw` | SELECT, INSERT, UPDATE (no DELETE/DDL) | business tables in scope | when write is enabled |

Generate the exact grant statements with `php artisan mcp:grants:print` (hand them to a DBA — the
command only prints, never executes). Two read-grant modes:

- **`--ro-mode=per-table`** (default) — `mcp_ro` gets `SELECT` on business tables only; secret tables
  (`mcp_*`, `oauth_*`, `sessions`, tokens) are excluded at the **database** level. This is the pilot /
  high-PII posture (DoD §13.7). MySQL cannot subtract a table from a `db.*` grant, so this is per-table.
- **`--ro-mode=schema`** — a single `GRANT SELECT ON db.*`, relying only on the app-level blocklist.
  Simpler, but it grants DB-level SELECT on auth/token/session tables too — **not for high-PII / pilot.**

Per-table means new tables aren't readable until granted. After adding a business table, run
`php artisan mcp:grants:diff` — it reads `mcp_ro`'s current grants and prints **only the missing**
`GRANT` lines (one or two), so you don't re-run the whole script. To move from `schema` to per-table:
`REVOKE SELECT ON db.* FROM mcp_ro` first, then apply `mcp:grants:print` (apply in one session — `mcp_ro`
loses read in between).

### `.env`

```dotenv
MCP_DB_HOST=127.0.0.1
MCP_DB_PORT=3306
MCP_DB_DATABASE=your_database

MCP_DB_CTL_USERNAME=mcp_ctl
MCP_DB_CTL_PASSWORD=

MCP_DB_RO_USERNAME=mcp_ro
MCP_DB_RO_PASSWORD=

# Public exposure (channel B, for claude.ai) — off by default
MCP_HTTP_ENABLED=false
MCP_HTTP_DOMAIN=mcp.example.com
MCP_ROUTE_PREFIX=mcp

# IP allowlist — on by default, local only
MCP_IP_ALLOWLIST_ENABLED=true
MCP_IP_ALLOWLIST=127.0.0.1,::1
```

## Install

```bash
composer require decocode/laravel-mcp
php artisan mcp:install
```

`mcp:install` publishes config + migrations, runs the migrations, and prints the manual steps
(the `mcp` auth guard for `config/auth.php` and the `routes/ai.php` entries) — these are printed
rather than auto-applied, because those files differ per project and version.

## Security model (summary)

- **Read-only** enforced by the `mcp_ro` SELECT-only user (DB level) + capability checks (app level).
- **Deletion** is impossible: no data-plane user ever holds DELETE, plus a global kill-switch.
- **PII** masked deny-by-default by column-name pattern — the shipped patterns cover credentials,
  financial/national ids *and* direct PII (e-mail, phone/mobile, person-name columns incl. no-underscore
  variants, street/address incl. `ip_address`, postal/zip code, date of birth, user-agent) — plus
  recursive scrubbing of PII nested in JSON / PHP-serialized columns (toggle `MCP_MASK_SCRUB_JSON`,
  default on); whole tables hidden by a blocklist. Matching is best-effort by column name: broad
  categories (`*address*`, `*ssn*`, `*zip*`, `*dob*`, `*birth*`) can't slip a variant, but person names can't go
  broad (a `*name*` would swallow entity names) — an unlabelled person column (`applicant`) or a bare
  `name`/`city` is NOT auto-masked, so review your schema and extend `masking.patterns`. Broad
  `*address*` also masks FK columns (`address_id`) — allowlist the ones you need for joins.
  Verification timestamps (`email_verified_at`) are un-masked by default. Un-mask a field via
  `masking.allowlist`, or soften it via `masking.partial` (keyed by exact column name, e.g. a column
  named `email` → domain).
- **Capabilities** (`read` / `write` / `command:run`) are stored in `mcp_*` tables and managed via
  artisan commands — never in the repo.

## Tools (read-only)

Each tool self-filters by the caller's capabilities — a `read`-only identity only ever sees the
read tools, and execution is re-checked server-side. Every call is recorded to a fail-closed audit
trail (if the call cannot be logged, no data is returned).

| Tool | Capability | What it does |
|---|---|---|
| `read_query` | `read` | Ad-hoc `SELECT` against `mcp_ro`. SELECT-only, single statement, forced LIMIT, blocked tables refused, sensitive columns + nested JSON masked. To keep masking from being evaded, the projection allows only `*` / `t.*` / bare columns / numeric literals — **function calls, expressions, aliasing, `UNION`/`INTERSECT`/`EXCEPT`, CTEs, `FROM`-subqueries and JSON extraction are rejected** (any of them can rename a column past name-based masking). Aggregates live in `count_rows`. |
| `count_rows` | `read` | Row count for a table, optional `WHERE`. The projection is fixed to `COUNT(*)` (never a column value), the table must be a plain non-blocked identifier, and the assembled query is guarded. Fills the aggregation gap `read_query` leaves. |
| `schema_describe` | `read` | Lists readable tables, or a table's columns. Blocked tables are hidden; each column notes whether its values are masked. Returns **no row data**. |
| `order_inspect` | `read` | Example domain tool — fetches one record + related rows by id. **Config-driven**; only registers once `mcp.tools.order_inspect` is set, so the package ships no project-specific schema. |

The server exposing these tools is registered in the app (not auto-edited by `mcp:install`).
Add to `routes/ai.php`:

```php
use Decocode\LaravelMcp\Servers\DiagnosticsServer;
use Laravel\Mcp\Facades\Mcp;

// Local/stdio (Claude Code, MCP Inspector via `php artisan mcp:inspector`):
Mcp::local('diagnostics', DiagnosticsServer::class);

// Public HTTPS (claude.ai), behind the mcp guard + IP allowlist + throttle:
Mcp::oauthRoutes();
Mcp::web('/mcp/diagnostics', DiagnosticsServer::class)
    ->middleware(['auth:mcp', 'mcp.ip-allowlist', 'throttle:'.config('mcp.http.throttle')]);
```

## Authorization & exposure

Tools resolve the calling identity through a dedicated **`mcp` auth guard** (Passport driver over
`McpServiceAccount`) — the application's own guards (`api`, `sanctum`, …) are untouched. Capability
gating denies by default, so an identity only sees and runs the tools its grants allow.

- **claude.ai (public HTTPS):** full OAuth 2.1 — `Mcp::oauthRoutes()` publishes the discovery
  (`.well-known/*`) + PKCE endpoints. Channel B is **off by default** (`MCP_HTTP_ENABLED`); enable it
  with an explicit domain, IP allowlist and throttle.
- **Claude Code (SSH/tunnel):** a Passport **personal access token** (scope `mcp:use`) as
  `Authorization: Bearer <token>`. Issue with `php artisan mcp:token:issue <account>` (shown once),
  revoke with `php artisan mcp:token:revoke <account>`.

```dotenv
MCP_HTTP_ENABLED=false            # channel B (public HTTPS) — opt in
MCP_HTTP_DOMAIN=mcp.example.com
MCP_HTTP_THROTTLE=60              # requests/minute on the MCP route
MCP_IP_ALLOWLIST_ENABLED=true     # default: local only
MCP_IP_ALLOWLIST=127.0.0.1,::1
```

> End-to-end OAuth against a live claude.ai connector and Claude Code is verified against a running
> application with Passport installed, so it is out of scope for this package's own test suite.
