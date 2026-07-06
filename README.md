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

# Channel B OAuth — service account (token `sub`) + operator hook
MCP_OAUTH_ACCOUNT=diag                 # provisioned via mcp:account:create
MCP_OAUTH_OPERATOR_GUARD=web           # guard holding the human operator
MCP_OAUTH_OPERATOR_GATE=mcp-operator   # Gate ability; or set mcp.oauth.operator_check in config
MCP_OAUTH_OPERATOR_LOGIN_ROUTE=login   # where to bounce an unauthenticated operator
# MCP_OAUTH_REDIRECT_ALLOWLIST defaults to the claude.ai/claude.com callbacks

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

### Channel A (Claude Code, Bearer) — the primary path

Beyond `composer require` + `mcp:install`, six steps get channel A live. `mcp:install` prints the
first two verbatim:

1. **`config/auth.php`** — add the `mcp` guard (Passport driver) + `mcp_service` provider
   (`McpServiceAccount`). Existing guards stay untouched.
2. **`routes/ai.php`** — `Mcp::local('diagnostics', DiagnosticsServer::class)`.
3. **Three MySQL accounts + grants** — `php artisan mcp:grants:print` emits the exact `GRANT`
   statements; **a DBA runs them** (the package never provisions DB users). This is where read-only
   is actually enforced (`mcp_ro` is SELECT-only at the DB level).
4. **`php artisan passport:install`** — keys + personal access client (required for Bearer tokens).
5. **Account → grant → token:** `mcp:account:create <name>` → `mcp:account:grant <name> read` →
   `mcp:token:issue <name>` (the token is shown once).
6. **Review masking against the project schema** — patterns match by column name and are best-effort:
   a bare `name`/`city` or an unlabelled person column (`applicant`) is **not** auto-masked. Extend
   `masking.patterns` / `masking.allowlist` per database before exposing data. Re-do this for every
   new project — a different schema means different PII.
   - **Run `php artisan mcp:masking:audit`** — a full-schema scan that lists PII-suspect columns that
     are **not** masked, table by table. Reviewing masking against a diff or a hand-built list misses
     gaps a full scan catches (legacy/foreign column names, a bare `ip`, `old`/`new` audit values);
     make this part of the deployment's Definition of Done. Add `--strict` to fail CI on any gap or
     any table it could not scan. The heuristic is **deliberately broad** — expect false positives to
     dismiss, and treat an empty result as "no suspect column slipped the current config", **not**
     proof of no PII. It fails (never green) on zero readable tables or an un-introspectable table.
   - For a column that is PII in one table but a harmless label in another (`customers.name` vs
     `tracks.name`), use **`masking.table_patterns`** (mask `table.column`) instead of a global
     pattern; `masking.table_allowlist` un-masks a column in one table only. Keep `table_allowlist`
     keys specific — a glob key (or a matching **view** name) lifts the mask across every match.

### Channel B (claude.ai, OAuth 2.1 + PKCE)

> **PREREQUISITE — Passport must be dedicated to MCP in this app.** Channel B configures Passport
> **globally**, so enabling it in an app that also uses Passport for its own OAuth will disrupt that
> OAuth. Concretely, with `http.enabled` + `manage_passport` (default on) the package sets: **(1)**
> the consent view — bound as a callback so only MCP connectors (redirect on the allowlist) get the
> MCP screen and other clients keep the default `passport::authorize`; **(2)** global token lifetimes
> (1d / 30d / 90d) for **all** Passport tokens; and you must set **(3)** `passport.guard = mcp_web`
> globally, which changes the OAuth resource owner for the whole app. If Passport is shared, either
> separate the concerns first or set `mcp.oauth.manage_passport=false` and wire Passport yourself.

`php artisan mcp:install --with-oauth` scaffolds channel B: it publishes the consent view and prints
the wiring. The package ships the whole operator-authorization layer — an operator middleware, the
consent screen, the redirect allowlist and the Passport bootstrap — so you only wire it up and fill
**one** project-specific hook.

1. **`config/auth.php`** — add a `mcp_web` **session** guard (over `mcp_service`) so the minted token's
   `sub` is the service account, not the human operator.
2. **`config/passport.php`** — `'guard' => 'mcp_web'` **only if Passport is used solely for MCP** in
   this app (it's a global setting; an app using Passport for other things must keep them separate).
3. **`bootstrap/app.php`** — append the operator gate to the `web` group:
   `$middleware->web(append: [\Decocode\LaravelMcp\Http\Middleware\EnsureMcpOperator::class])`.
4. **Answer "who may authorize a connector"** — the one project-specific edit:
   - **Gate ability** (simple): `Gate::define('mcp-operator', fn ($u) => $u->hasRole('Super Admin'))`,
     then `mcp.oauth.operator_gate = 'mcp-operator'` (+ `operator_guard`, `operator_login_route`).
   - **`McpOperatorCheck` class** (advanced): set `mcp.oauth.operator_check` to a class implementing
     `authorize(Request): bool` + `serviceAccountId(): ?int` — wins over the gate; use it for logic a
     Gate can't express or a dynamically chosen service account.
5. **`MCP_HTTP_ENABLED=true`** + a public HTTPS endpoint (a dedicated domain or a tunnel), and point
   `mcp.oauth.account` at the provisioned service account.

The consent screen is **always shown — never auto-approved.** Client registration is public + dynamic,
so a silent approve would let one phished operator click authorize an attacker's client; the redirect
allowlist pins the delivery channel (claude.ai), the consent click pins the recipient. The package
applies this Passport bootstrap automatically when channel B is on (opt out with
`mcp.oauth.manage_passport=false`). Make your own RODO/GDPR decisions on what to mask.

> Channel A is repeatable and mostly config. Channel B adds the wiring above — five steps, one of them
> the operator hook.

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
  named `email` → domain). **Table-qualified** rules (`masking.table_patterns` /
  `masking.table_allowlist`) close the bare-`name` gap at the source — mask a column only in the
  table(s) where it is PII — and apply wherever the tool knows the source table (`schema_describe`,
  `count_rows`, `order_inspect`, and single-table `read_query` SELECTs; a JOIN result stays
  name-based). Audit coverage with `php artisan mcp:masking:audit`.
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
