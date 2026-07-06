# Changelog

All notable changes to `decocode/laravel-mcp` are documented here.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/).

## [0.3.1] - 2026-07-06

### Fixed — `read_query` now rejects JOINs (PII leak)
- A JOIN (or comma-join) in `read_query` produced a flat result whose columns come from more than one
  table. Table-qualified masking (`table_patterns` / `table_allowlist`) keys on a **single** source
  table, so it could not attribute a JOINed column and silently fell back to name-based masking —
  letting a column masked **only** per-table (e.g. `customers.name`) surface raw through a trivial
  `SELECT c.name FROM customers c JOIN orders o …`. `QueryGuard::guardProjection` now **rejects JOINs
  and comma-joins** outright, the same way it already rejects UNION / CTEs / `FROM`-subqueries /
  aliasing (all evade name-based masking). `read_query` is single-table by design; `count_rows` and
  `order_inspect` own their SQL and are unaffected. **Any deployment using `table_patterns` should
  upgrade.**

### Improved — `PiiHeuristic` now flags secrets & crypto material
- `mcp:masking:audit` missed key/secret columns a name-based review also misses (`hmac_key`,
  Web-Push `p256dh_key`/`auth_key`, `laravel_session_id`). Added: `hmac`, `session`, `hash`, `cipher`,
  `nonce`, `credential` (substring) and whole-token `key`, `salt`, `jwt`, `otp` (so `*_key` is flagged
  without swallowing `monkey`/`turkey`). Heuristic only — a hit is an audit suggestion to confirm.

## [0.3.0] - 2026-07-06

### Added — table-qualified masking
- The same column name can be PII in one table and a harmless label in another (`customers.name` is a
  person, `tracks.name` an entity; `revisions.old`/`new` hold audit values that elsewhere are not PII).
  Name-based patterns cannot tell them apart, so two per-table maps now layer on top:
  **`masking.table_patterns`** (`table.column` → mask) and **`masking.table_allowlist`**
  (`table.column` → un-mask, so a globally-masked column such as a FK can be exposed in one table
  only). Keys and column entries are glob patterns; a `'*'` table key applies to every table.
- Applied wherever the tool knows the source table: `schema_describe`, `count_rows` (oracle guard),
  `order_inspect`, and **single-table `read_query` SELECTs** (`QueryGuard::singleTableFrom` resolves
  the table; a JOIN / comma-join / non-SELECT yields no table and masking falls back to name-based —
  never weaker than before). Nested JSON keys have no table context and stay name-based.
- **Backwards compatible:** `ColumnMasker::shouldMask/maskValue/maskRow` take an optional `?string
  $table` (default `null` → exactly the pre-0.3.0 name-based behaviour). No config change required.

### Added — `mcp:masking:audit`
- Full-schema masking audit: scans every readable table and flags columns that **look** like PII
  (`PiiHeuristic`, deliberately broader than the masking patterns, incl. Polish/legacy spellings)
  but are **not** masked (table-aware). This is the answer to a hard lesson — reviewing masking
  against a diff or a hand-built list passes gaps a full scan catches (a legacy mail/phone column
  under a non-obvious name, `revisions.old/new`, a bare `ip`). Meant to be part of a deployment's
  Definition of Done.
- `--json` for machine-readable output; `--strict` exits non-zero on any gap (CI / DoD gate). Read-only
  (introspects `information_schema` — MySQL-only — never any data).

## [0.2.0] - 2026-07-05

### Added — channel B (claude.ai OAuth) scaffolding
- The operator-authorization layer for claude.ai connectors now ships with the package, so a project
  no longer hand-writes it. Previously channel B required app-side glue (an operator middleware, a
  consent view, a redirect allowlist, Passport bootstrap); those are now built in.
- **`EnsureMcpOperator` middleware** (alias `mcp.operator`) guards `/oauth/authorize`: it authorizes
  the operator, enforces the `redirect_uri` allowlist, and logs the read-only service account in as the
  OAuth resource owner (its id becomes the token `sub`). Register it in the `web` group.
- **"Who may authorize a connector"** is the one project-specific decision, answered two ways: a Gate
  ability (`mcp.oauth.operator_gate`, the simple path) or an `McpOperatorCheck` class
  (`mcp.oauth.operator_check`, which wins when set — for logic a Gate can't express or a dynamically
  chosen service account).
- **Consent view** (`mcp::oauth-consent`) is shipped and shown by default — always, never auto-approved
  (public + dynamic client registration makes a silent approve a phishing vector). Override via
  `php artisan vendor:publish --tag=mcp-oauth-views`.
- **Passport bootstrap** for channel B (consent view binding + short token lifetimes) is applied
  automatically when `http.enabled` is on; opt out with `mcp.oauth.manage_passport=false` if the app
  manages Passport itself.
- **`mcp:install --with-oauth`** publishes the consent view and prints the channel-B wiring (the
  `mcp_web` session guard, the operator middleware, and the operator hook).
- New config block `mcp.oauth.*` (account, redirect allowlist, operator hook, web guard, token TTLs).
  Backwards compatible: everything is inert unless channel B is enabled.

### Security (channel B hardening)
- **Consent is now enforced by the package, not assumed.** The operator middleware forces
  `prompt=consent` on every authorize, so Passport cannot skip the screen via a persisted grant on
  the shared service account (`skipsAuthorization` / `hasGrantedScopes`) — closing an auto-approve
  path that a client reusing a stable `client_id` could otherwise exploit.
- **The operator gate fails closed.** With neither `operator_gate` nor `operator_check` configured,
  channel B refuses (403) instead of letting any authenticated user connect a connector.
- **Consent view is scoped to MCP connectors.** Bound as a callback, so only clients whose redirect is
  on the allowlist get the MCP screen; other Passport clients keep the default authorize view.
- Revoked service accounts are treated as absent (never become an OAuth resource owner).

## [0.1.0] - 2026-07-04

First public release.

### Changed — default column masking now covers direct PII
- `masking.patterns` ships with direct-PII patterns by default (e-mail, phone/mobile, person-name
  columns — `first_name`/`firstname`/`surname`/… and variants — street/address incl. `ip_address`,
  postal/zip code, date of birth, user-agent) and broadens the national-id coverage (`passport`,
  `ssn`, `tax_id`) alongside the existing credential/financial ones. Previously only secrets were
  masked, so a fresh deployment surfaced e-mails, phones, names and addresses in the clear until each
  project added its own patterns — at odds with the stated deny-by-default posture. A project that
  needs a field for diagnosis can un-mask it via `allowlist` or soften it via `partial`.
- Matching is column-name based and best-effort: categories that can be matched broadly are
  (`*address*`, `*ssn*`, `*zip*`, `*dob*`, `*birth*`), but person names cannot (a broad `*name*`
  collides with entity/lookup columns and the masker has no table context), so names are enumerated
  for common variants. An unlabelled person column (`applicant`, `holder`) or a bare `name`/`city` is
  NOT auto-masked — review your schema and extend `masking.patterns` for project-specific columns.
- Address is matched broadly (`*address*`) so no address column name can slip through; this also masks
  FK/morph columns (`address_id`, `*_address_id`, `addressable_type`) — allowlist the specific ones a
  project needs for joins. `email_verified_at` / `phone_verified_at` / `mobile_verified_at` are
  un-masked by default (verification timestamps carry no PII but match `*email*` / `*phone*`).
- `partial` is keyed by EXACT column name (not a pattern): `'email' => 'email'` softens only a column
  literally named `email`; `customer_email` is still fully redacted by `*email*`.
- Note: because `count_rows` refuses a `WHERE` that references a masked column (existence-oracle
  guard), the wider default masking also narrows its filter surface — a masked column can't be
  filtered on until it is allowlisted.

### Changed — MySQL grant generation (per-table §13.7)
- `mcp:grants:print` reworked: introspects real tables (version-robust across Passport 11/12/13) and,
  by default (`--ro-mode=per-table`), grants `mcp_ro` `SELECT` on business tables ONLY — secret tables
  are excluded at the DB level, mirroring the blocklist. Replaces the previous `GRANT db.*` + per-table
  `REVOKE` (which is invalid MySQL — error 1147, you cannot subtract a table from a schema-wide grant).
  `--ro-mode=schema` keeps the old `GRANT db.*` for blocklist-only setups (does NOT meet DoD §13.7, and
  grants DB-level SELECT on auth/token/session tables — not for high-PII / pilot use).
- `mcp:grants:diff` (new): prints only the read grants `mcp_ro` is still missing (for newly added
  tables), read from `SHOW GRANTS` over the mcp_ro connection — one or two `GRANT` lines instead of the
  whole script. A hard `NEVER_READ` floor keeps secrets out of the read grant independent of the blocklist.
- Introspection is scoped to the target database (`Schema::getTables()` with no schema returns tables
  from every database the connection can see); shared logic lives in `Support\GrantPlanner`.

### Added — F3 (auth, tokens & exposure — package side)
- `mcp:token:issue` / `mcp:token:revoke` — Passport personal access tokens (scope `mcp:use`) as the
  Claude Code Bearer credential; issue guards against unknown/disabled accounts, plaintext shown once.
- `mcp:install` publishes + migrates automatically and now GUIDES the manual steps for Passport
  (`passport:install`, incl. personal access client), the `Mcp::oauthRoutes()` + `Mcp::web(...)`
  route registration (with `auth:mcp` + IP allowlist + throttle), and the account/token bootstrap.
  Sensitive files (`config/auth.php`, `routes/ai.php`) are printed, not auto-edited (hybrid install).
- `mcp.http.throttle` config (requests/minute) for the public route.
- README: authorization & exposure section (claude.ai OAuth vs Claude Code Bearer; channel B toggles).
- `ResolvesMcpAccount` trait deduplicates account lookup across the account/token commands.
- Live OAuth e2e (claude.ai connector + Claude Code) remains **pilot** scope (needs a running app with
  Passport) — see `docs/PLAN.md` §13.

### Added — F0 (scaffold)
- Package skeleton on top of `laravel/mcp`: service provider, publishable config,
  dedicated `mcp_ctl` / `mcp_ro` connection registrar, `mcp.ip-allowlist` middleware.
- `McpServiceAccount` / `McpAbility` models and `mcp_accounts`, `mcp_abilities`,
  `mcp_audit_log` migrations.
- Hybrid `mcp:install` and `mcp:grants:print` commands. `DiagnosticsServer` skeleton.

### Added — F1 (security core)
- Capability model: `Capability` registry, `CapabilityResolver` +
  `DatabaseCapabilityResolver` (unknown → deny, global `delete` kill-switch).
- Read guards: `QueryGuard` (SELECT-only, single-statement, file-exfiltration block,
  enforced LIMIT), `ColumnMasker` (deny-by-default column masking + email/last4 partial
  maskers), `TableBlocklist`.
- `AuditLogger` on the control-plane connection.
- Account management: `mcp:account:create|list|grant|revoke`.

### Added — F2 (read-only tools)
- MCP tools wired into `DiagnosticsServer`, each self-filtering by capability
  (conditional registration) and re-checking on execution:
  - `read_query` — `SELECT` over `mcp_ro` through `QueryGuard::sanitize()`, table blocklist and
    `ColumnMasker`. To stop masking being evaded, `QueryGuard::guardProjection` allows only
    `*` / `t.*` / bare columns / numeric literals in the projection and rejects function calls,
    expressions, aliasing, `UNION`/`INTERSECT`/`EXCEPT`, CTEs, subqueries/derived tables in `FROM`,
    and JSON extraction (`json_extract` / `json_table` / `->` / `->>`) — so a result column name
    always maps back to a real source column the masker can see (a function's auto-alias could be
    truncated or wrapped past the pattern). The blocklist scans every identifier (comma-joins,
    subqueries, back-ticked and ANSI-quoted names included), not just the token after `FROM`/`JOIN`.
    Aggregates are not available in the raw projection; use `count_rows`.
  - `count_rows` — aggregate row count for a table with an optional `WHERE`. The projection is
    fixed to `COUNT(*)` (so no column value is ever surfaced), the table must be a plain non-blocked
    identifier, and the assembled query passes `QueryGuard::validate` + the blocklist scan. The
    `WHERE` fragment may not reference a masked column or use a set operation — closing the
    count-as-oracle path for PII.
  - `schema_describe` — table / column introspection respecting the blocklist; flags masked columns
    and returns no row data.
  - `order_inspect` — config-driven example domain tool (`mcp.tools.order_inspect`), hidden until
    configured so the package ships no project-specific schema.
- `AbstractDiagnosticTool` base: identity resolution via the `mcp` guard, capability gate,
  and fail-closed audit around every call.
- **PR-001:** `JsonScrubber` recursively masks PII nested in JSON/serialized columns by key name;
  wired into `ColumnMasker::maskRow()` (toggle `masking.scrub_json`, default on).

### Security
- **PR-010:** `AuditLogger` is now fail-closed — an encode failure (invalid UTF-8 via
  `JSON_INVALID_UTF8_SUBSTITUTE`, or `INF`/`NAN`) or a persist failure raises `AuditException`, and
  tools return no data rather than leak an unlogged result.
- `read_query` closes several masking-evasion vectors surfaced in review: column aliasing /
  expressions / function calls (allow-list of `*` / `t.*` / bare column / numeric only), `UNION`
  grafting a sensitive column under the first SELECT's name, a derived-table alias
  (`FROM (SELECT password AS x …) t`) renaming PII, `json_extract` / `JSON_TABLE` pulling values
  past the JSON scrubber, and blocked tables smuggled through a comma-join or ANSI-quoted name.
- IP allowlist fails closed when enabled with an empty list.
- Query guard normalises whitespace (blocks padded `INTO  OUTFILE`) and anchors LIMIT
  detection to statement end (subquery `LIMIT` no longer suppresses the outer cap).

### Changed — PR review hardening
- PII masking patterns broadened to catch naming variants (`*nip*`, `*pesel*`, `*card*`, `*cvv*`, `*cvc*`).
- Capability scope is fail-closed: a scoped grant queried without a scope is denied.
- Added a `write` kill-switch (`MCP_WRITE_ENABLED`), symmetric to `delete`.
- `QueryGuard::sanitize()` returns a single validated, comment-free, LIMIT-capped statement; the
  FORBIDDEN scan ignores string literals (so `WHERE action = 'delete'` is allowed).
- `mcp:grants:print` defaults `--host` to `127.0.0.1` (later reworked to per-table grants — see below).
- Unique constraints on `mcp_accounts.name` and `mcp_abilities(account_id, capability)`.
