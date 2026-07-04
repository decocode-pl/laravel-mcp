<?php

declare(strict_types=1);

namespace Decocode\LaravelMcp\Support;

use Decocode\LaravelMcp\Security\PatternMatcher;
use Decocode\LaravelMcp\Security\TableBlocklist;
use Illuminate\Support\Facades\Schema;
use Throwable;

/**
 * Shared grant planning for the mcp:grants:* commands. Introspects the schema,
 * computes which tables the read user (mcp_ro) may see, and parses live grants
 * to produce a delta. Pure of side effects — it never GRANTs or mutates.
 */
class GrantPlanner
{
    /** @var list<string> */
    public const CONTROL_TABLES = ['mcp_accounts', 'mcp_abilities', 'mcp_audit_log'];

    /**
     * Hard security floor: patterns mcp_ro is NEVER granted, independent of the
     * configurable blocklist — narrowing the blocklist cannot expose them.
     *
     * @var list<string>
     */
    public const NEVER_READ = [
        'mcp_*', 'oauth_*',
        'sessions', 'personal_access_tokens', 'password_reset_tokens', 'password_resets',
        'telescope_*',
    ];

    /** @var list<string> */
    private const OAUTH_FALLBACK = [
        'oauth_auth_codes', 'oauth_access_tokens', 'oauth_refresh_tokens', 'oauth_clients', 'oauth_device_codes',
    ];

    /**
     * Table names of the TARGET database (the one the grants are for), read via
     * the default connection (the app DB user, which sees every table). Scoped
     * to that schema — `Schema::getTables()` with no schema returns tables from
     * EVERY database the connection can see, which would stamp foreign tables
     * with our db name. Null when the schema cannot be read.
     *
     * @return list<string>|null
     */
    public function tableNames(): ?array
    {
        try {
            return array_map(
                fn (array $t): string => (string) $t['name'],
                Schema::getTables(self::targetSchema())
            );
        } catch (Throwable) {
            return null;
        }
    }

    /**
     * The database to introspect — the one the grants/tools target. Null means
     * "the connection's default schema". `Schema::getTables()` with no schema
     * returns tables from EVERY database the connection can see, so callers must
     * pass this to stay scoped to the target database.
     */
    public static function targetSchema(): ?string
    {
        $schema = config('mcp.db.database');

        return $schema !== null && $schema !== '' ? (string) $schema : null;
    }

    /**
     * Business tables mcp_ro may read: every table minus the hard floor minus
     * the configurable blocklist. Null when the schema cannot be read.
     *
     * @param  list<string>|null  $all  pre-fetched table list (avoids a second introspection)
     * @return list<string>|null
     */
    public function businessTables(?array $all = null): ?array
    {
        $all ??= $this->tableNames();

        if ($all === null) {
            return null;
        }

        $blocklist = TableBlocklist::fromConfig();

        return array_values(array_filter(
            $all,
            fn (string $t): bool => ! $this->isSecretFloor($t) && ! $blocklist->isBlocked($t)
        ));
    }

    /**
     * oauth_* tables the control-plane owns — introspected (version-robust) or a
     * Passport 12/13 fallback when the schema cannot be read.
     *
     * @param  list<string>|null  $all
     * @return list<string>
     */
    public function oauthTables(?array $all): array
    {
        if ($all === null) {
            return self::OAUTH_FALLBACK;
        }

        return array_values(array_filter($all, fn (string $t): bool => str_starts_with(strtolower($t), 'oauth_')));
    }

    public function isSecretFloor(string $table): bool
    {
        $table = strtolower($table);

        foreach (self::NEVER_READ as $pattern) {
            if (PatternMatcher::matches($pattern, $table)) {
                return true;
            }
        }

        return false;
    }

    /** Escape a MySQL identifier for interpolation between back-ticks. */
    public function ident(string $name): string
    {
        return str_replace('`', '``', $name);
    }

    /**
     * Parse the rows of `SHOW GRANTS` into the set of tables that already hold a
     * SELECT for the target database, plus whether a schema-wide (`db.*`) SELECT
     * is present (i.e. the account is in "schema mode").
     *
     * @param  iterable<mixed>  $rows
     * @return array{tables: list<string>, schemaWide: bool}
     */
    public static function parseGrantedSelectTables(iterable $rows, string $db): array
    {
        $tables = [];
        $schemaWide = false;

        foreach ($rows as $row) {
            $line = is_string($row) ? $row : (string) (array_values((array) $row)[0] ?? '');

            if (preg_match('/^GRANT\s+(.+?)\s+ON\s+(\S+)\s+TO\b/i', $line, $m) !== 1) {
                continue;
            }

            // Table-level SELECT (or ALL) only — a column grant `SELECT (a, b)`
            // does not make the whole table readable, so it is not counted.
            $hasTableSelect = preg_match('/\bSELECT\b(?!\s*\()/i', $m[1]) === 1
                || preg_match('/\bALL\s+PRIVILEGES\b/i', $m[1]) === 1;

            if (! $hasTableSelect) {
                continue;
            }

            $object = $m[2];

            if (preg_match('/^`?([^`.]+)`?\.\*$/', $object, $mm) === 1) {
                // `db`.* → schema-wide for our db; *.* (global) covers it too.
                if ($mm[1] === '*' || strtolower($mm[1]) === strtolower($db)) {
                    $schemaWide = true;
                }
            } elseif (preg_match('/^`?([^`.]+)`?\.`?(.+?)`?$/', $object, $mm) === 1) {
                if (strtolower($mm[1]) === strtolower($db)) {
                    $tables[] = str_replace('``', '`', $mm[2]);
                }
            }
        }

        return ['tables' => array_values(array_unique($tables)), 'schemaWide' => $schemaWide];
    }

    /**
     * Business tables that do NOT yet hold a SELECT grant (case-insensitive).
     *
     * @param  list<string>  $business
     * @param  list<string>  $granted
     * @return list<string>
     */
    public static function missing(array $business, array $granted): array
    {
        $have = array_map('strtolower', $granted);

        return array_values(array_filter($business, fn (string $t): bool => ! in_array(strtolower($t), $have, true)));
    }
}
