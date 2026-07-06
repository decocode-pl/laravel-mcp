<?php

declare(strict_types=1);

return [

    /*
    |--------------------------------------------------------------------------
    | Database connections (data-plane + control-plane)
    |--------------------------------------------------------------------------
    | The package registers dedicated MySQL connections backed by table-scoped
    | users. `read` (mcp_ro) is SELECT-only — the HARD read-only guarantee.
    | `control` (mcp_ctl) owns only the mcp_, oauth_ and audit tables. `write`
    | (mcp_rw) is provisioned later, only when write capability is enabled.
    */
    'db' => [
        'host' => env('MCP_DB_HOST', '127.0.0.1'),
        'port' => env('MCP_DB_PORT', '3306'),
        'database' => env('MCP_DB_DATABASE'),
        'charset' => 'utf8mb4',
        'collation' => 'utf8mb4_unicode_ci',

        'control' => [
            'username' => env('MCP_DB_CTL_USERNAME'),
            'password' => env('MCP_DB_CTL_PASSWORD'),
        ],
        'read' => [
            'username' => env('MCP_DB_RO_USERNAME'),
            'password' => env('MCP_DB_RO_PASSWORD'),
        ],
        'write' => [
            'username' => env('MCP_DB_RW_USERNAME'),
            'password' => env('MCP_DB_RW_PASSWORD'),
        ],
    ],

    // Connection used for the package's own migrations (null = default connection,
    // i.e. same database as the app). Point elsewhere for a physically separate MCP DB.
    'migration_connection' => env('MCP_MIGRATION_CONNECTION'),

    /*
    |--------------------------------------------------------------------------
    | Capabilities
    |--------------------------------------------------------------------------
    | Global kill-switches for `delete` and `write`: even an account granted
    | the capability cannot exercise it until the matching switch is explicitly
    | turned on. Both default to OFF.
    */
    'capabilities' => [
        'delete_enabled' => (bool) env('MCP_DELETE_ENABLED', false),
        'write_enabled' => (bool) env('MCP_WRITE_ENABLED', false),
    ],

    /*
    |--------------------------------------------------------------------------
    | Read restriction — Layer A: table blocklist (deny-list)
    |--------------------------------------------------------------------------
    | Whole tables never readable via MCP (queries + schema introspection).
    | Package ships safe defaults; extend per project via MCP_READ_BLOCKED_TABLES
    | or in the published config. Wildcards (prefix*) supported.
    */
    'read' => [
        'blocked_tables' => array_values(array_unique(array_merge([
            'mcp_*', 'oauth_*',
            'sessions', 'password_resets', 'password_reset_tokens', 'personal_access_tokens',
            'failed_jobs', 'jobs', 'job_batches', 'cache', 'cache_locks', 'telescope_*',
        ], array_filter(array_map('trim', explode(',', (string) env('MCP_READ_BLOCKED_TABLES', ''))))))),

        // Connection tools read through — SELECT-only mcp_ro by default.
        'connection' => env('MCP_READ_CONNECTION', 'mcp_ro'),

        'max_rows' => (int) env('MCP_READ_MAX_ROWS', 500),
        'timeout_seconds' => (int) env('MCP_READ_TIMEOUT', 10),
    ],

    /*
    |--------------------------------------------------------------------------
    | Read restriction — Layer B: column masking (always ON, deny-by-default)
    |--------------------------------------------------------------------------
    | Columns whose name matches a pattern are masked in output regardless of
    | which tool/query surfaced them. `allowlist` un-masks specific columns;
    | `partial` maps a column to a partial masker (recognisable, not readable).
    */
    'masking' => [
        'patterns' => [
            // Credentials & secrets
            '*password*', '*passwd*', '*secret*', 'remember_token', '*token*',
            '*api_key*', '*apikey*', '*api_secret*',
            // Financial / national identifiers
            '*bank*', '*iban*', '*pesel*', '*nip*', '*passport*', '*ssn*',
            '*tax_id*', '*card*', '*cvv*', '*cvc*',
            // Direct PII present in virtually every app — masked by default to
            // honour deny-by-default. Un-mask a field a project needs for
            // diagnosis via `allowlist`, or soften it via `partial` (which is
            // keyed by EXACT column name, not a pattern — see below). Categories
            // that CAN be matched broadly are, so no column-name variant slips
            // through: address (`*address*` — masks FK/morph `address_id` /
            // `addressable_type` too; allowlist the ones you need for joins),
            // ssn, zip, dob, birth. Person names CANNOT go broad — a bare
            // `*name*` collides with entity/lookup names (event/category), and
            // the masker is column-name only (no table context) — so names are
            // enumerated for common variants (with/without underscore). This is
            // best-effort: a bare `name`, `city`, or an unlabelled person column
            // (e.g. `applicant`, `holder`) is NOT auto-masked — review your
            // schema and add project-specific patterns for anything unusual.
            '*email*', '*phone*', '*mobile*', '*first_name*', '*firstname*',
            '*last_name*', '*lastname*', '*surname*', '*full_name*', '*fullname*',
            '*middle_name*', '*maiden_name*', '*given_name*', '*family_name*',
            '*street*', '*address*', '*postal*', '*postcode*', 'post_code',
            '*zip*', '*birth*', '*dob*', '*user_agent*',
        ],
        // Un-masked even though they match a pattern: verification timestamps
        // carry no PII (just "when verified") but match `*email*` / `*phone*` /
        // `*mobile*`. Also keeps them filterable in `count_rows`.
        'allowlist' => ['email_verified_at', 'phone_verified_at', 'mobile_verified_at'],
        // Keyed by EXACT column name (NOT a pattern): `'email' => 'email'` softens
        // only a column literally named `email`; `customer_email` still matches
        // `*email*` and is fully redacted. List each concrete column you want softened.
        'partial' => [],     // e.g. 'email' => 'email', 'card_number' => 'last4'
        'placeholder' => '[masked]',

        // Table-qualified masking (0.3.0): the same column name can be PII in one
        // table and a harmless label in another — `customers.name` is a person,
        // `tracks.name` an entity; `revisions.old`/`new` hold values that in other
        // tables are not PII. Name-based patterns above cannot tell them apart
        // (they see only the column name), so these two maps add per-table
        // precision on top. Applied ONLY when the tool knows the source table
        // (schema_describe, count_rows, order_inspect, and single-table SELECTs in
        // read_query — a JOIN result has no single source table and stays
        // name-based). Keys AND column entries are glob patterns (`*` wildcard);
        // a `'*'` table key applies to every table.
        //
        // table_patterns — mask these columns within matching tables:
        'table_patterns' => [
            // 'customers' => ['name'],            // person name in this table only
            // 'revisions' => ['old', 'new'],      // audit before/after values
            // '*'         => ['ip', 'ip_forwarded'],  // any table with a raw IP
        ],
        // table_allowlist — un-mask these columns within matching tables. This is
        // the most specific rule and wins over everything, so it can expose a
        // globally-masked column in ONE table without exposing it everywhere — e.g.
        // a FK the broad `*address*` pattern masks, needed for joins in one table.
        // CAUTION: a glob table key (`'*'`, `orders*`) lifts the mask across EVERY
        // matching table (and view) — keep keys specific. `mcp:masking:audit` will
        // flag anything you accidentally leave un-masked.
        'table_allowlist' => [
            // 'orders' => ['address_id'],
        ],

        // PR-001: recursively mask PII nested inside JSON/serialized columns
        // (e.g. print_job_payloads) by key name, not just top-level columns.
        // (Nested keys carry no table context — they use the name-based rules.)
        'scrub_json' => (bool) env('MCP_MASK_SCRUB_JSON', true),
    ],

    /*
    |--------------------------------------------------------------------------
    | Artisan commands over MCP (deny-by-default allowlist)
    |--------------------------------------------------------------------------
    | Never expose "*". `denylist` is shipped by the package and cannot be
    | overridden by the allowlist. Each allowlisted command declares required
    | capability + per-tier argument policy (forced/blocked/allowed).
    */
    'commands' => [
        'enabled' => (bool) env('MCP_COMMANDS_ENABLED', false),

        // Hard denylist — allowlist can never re-enable these.
        'denylist' => [
            'mcp:*', 'migrate*', 'db:wipe', 'db:seed', 'tinker',
            'queue:flush', 'queue:clear', 'key:generate', 'config:*', 'schema:*',
        ],

        // Per-command policy. Empty by default — opt in explicitly per project.
        // 'orders:reconcile' => [
        //     'tiers' => [
        //         'read'  => ['options' => ['--dry-run' => ['force' => true], '--execute' => ['block' => true]]],
        //         'write' => ['options' => ['--execute' => ['allow' => true]]],
        //     ],
        //     'arguments' => ['order_id' => ['allow' => true, 'type' => 'int']],
        //     'timeout' => 60,
        // ],
        'allowlist' => [],
    ],

    /*
    |--------------------------------------------------------------------------
    | Authorization
    |--------------------------------------------------------------------------
    | Guard that authenticates the MCP identity. The `mcp` Passport guard is
    | wired in F3 (see the mcp:install snippet). Tools resolve the calling
    | account through it to gate capabilities.
    */
    'auth' => [
        'guard' => env('MCP_AUTH_GUARD', 'mcp'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Domain tools (config-driven, ship nothing project-specific)
    |--------------------------------------------------------------------------
    | order.inspect only registers once configured for a project, so the public
    | package carries no client table names. Example:
    |
    | 'order_inspect' => [
    |     'table' => 'orders', 'id_column' => 'id',
    |     'related' => [['table' => 'order_items', 'foreign_key' => 'order_id', 'limit' => 50]],
    | ],
    */
    'tools' => [
        'order_inspect' => [],
    ],

    /*
    |--------------------------------------------------------------------------
    | Transport & exposure
    |--------------------------------------------------------------------------
    | Channel A (SSH/tunnel) is the default, infra-managed path — nothing to
    | toggle here. Channel B (public HTTPS for claude.ai) is OFF by default.
    */
    'http' => [
        'enabled' => (bool) env('MCP_HTTP_ENABLED', false),
        'domain' => env('MCP_HTTP_DOMAIN'),
        'prefix' => env('MCP_ROUTE_PREFIX', 'mcp'),

        // Rate limit for the public MCP route (requests/minute), applied via the
        // throttle middleware in the routes/ai.php snippet.
        'throttle' => (int) env('MCP_HTTP_THROTTLE', 60),
    ],

    'ip_allowlist' => [
        'enabled' => (bool) env('MCP_IP_ALLOWLIST_ENABLED', true),
        'allowed' => array_values(array_filter(array_map(
            'trim',
            explode(',', (string) env('MCP_IP_ALLOWLIST', '127.0.0.1,::1'))
        ))),
    ],

    /*
    |--------------------------------------------------------------------------
    | Channel B — claude.ai OAuth (operator gate + consent)
    |--------------------------------------------------------------------------
    | claude.ai connects via full OAuth 2.1 + PKCE. The package ships the whole
    | operator-authorization layer (the `mcp.operator` middleware + consent view
    | + Passport bootstrap); a project only wires it up and fills ONE hook —
    | "who may authorize a connector". Two ways to answer that:
    |
    |   • operator_gate  — a Gate ability checked against the operator guard's
    |     user (the simple, idiomatic path). Define it in a service provider:
    |         Gate::define('mcp-operator', fn ($u) => $u->hasRole('Super Admin'));
    |
    |   • operator_check — a class implementing Contracts\McpOperatorCheck
    |     (authorize(Request): bool + serviceAccountId(): ?int). Takes precedence
    |     over the gate when set; use it for logic a Gate can't express, or to
    |     pick the service account dynamically.
    |
    | Everything here is inert until channel B is enabled (`http.enabled`).
    */
    'oauth' => [
        // Service account whose id becomes the issued token's `sub` (resource
        // owner). Provision it with `mcp:account:create <name>` + grant `read`.
        'account' => env('MCP_OAUTH_ACCOUNT'),

        // Only these redirect_uri values may receive an authorization code —
        // client registration is public, so this pins the delivery channel to
        // claude.ai. (The always-on consent screen pins the recipient.)
        'redirect_allowlist' => array_values(array_filter(array_map('trim', explode(',', (string) env(
            'MCP_OAUTH_REDIRECT_ALLOWLIST',
            'https://claude.ai/api/mcp/auth_callback,https://claude.com/api/mcp/auth_callback'
        ))))),

        // Operator hook (see block above). operator_check wins over operator_gate.
        'operator_guard' => env('MCP_OAUTH_OPERATOR_GUARD', 'web'),
        'operator_gate' => env('MCP_OAUTH_OPERATOR_GATE'),       // e.g. 'mcp-operator'
        'operator_check' => null,                                // e.g. App\Mcp\SuperAdminOperator::class
        'operator_login_route' => env('MCP_OAUTH_OPERATOR_LOGIN_ROUTE', 'login'),

        // Session guard the service account is logged into as the OAuth resource
        // owner. Register it in config/auth.php (see `mcp:install --with-oauth`).
        'web_guard' => env('MCP_OAUTH_WEB_GUARD', 'mcp_web'),

        // Let the package configure Passport for channel B (consent view + short
        // token lifetimes + never auto-approve). Turn OFF if your app already
        // manages Passport itself and you want full control.
        'manage_passport' => (bool) env('MCP_OAUTH_MANAGE_PASSPORT', true),
        'token_ttl_days' => (int) env('MCP_OAUTH_TOKEN_TTL_DAYS', 1),
        'refresh_ttl_days' => (int) env('MCP_OAUTH_REFRESH_TTL_DAYS', 30),
        'personal_ttl_days' => (int) env('MCP_OAUTH_PERSONAL_TTL_DAYS', 90),
    ],

    /*
    |--------------------------------------------------------------------------
    | Audit log (control-plane)
    |--------------------------------------------------------------------------
    */
    'audit' => [
        'connection' => 'mcp_ctl',
        'table' => 'mcp_audit_log',
    ],
];
