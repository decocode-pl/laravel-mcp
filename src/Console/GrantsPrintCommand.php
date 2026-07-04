<?php

declare(strict_types=1);

namespace Decocode\LaravelMcp\Console;

use Decocode\LaravelMcp\Support\GrantPlanner;
use Illuminate\Console\Command;

/**
 * Prints the CREATE USER / GRANT statements for the MCP MySQL accounts, ready to
 * hand to a DBA. It only READS the schema (to build a version-correct, accurate
 * table list) — it never GRANTs, REVOKEs or mutates anything itself.
 *
 * The read grant for mcp_ro has two modes:
 *  - per-table (default) — SELECT is granted table-by-table on business tables
 *    only, so secret tables are excluded at the DATABASE level (DoD §13.7). This
 *    mirrors the app-level TableBlocklist. Re-run (or `mcp:grants:diff`) after
 *    adding business tables.
 *  - schema — a single `GRANT SELECT ON db.*`, relying solely on the app-level
 *    blocklist. Simpler, but no DB-level exclusion. MySQL cannot subtract a table
 *    from a schema-wide grant (`REVOKE ON db.tbl` after `GRANT ON db.*` errors
 *    1147), so there is no "grant all then revoke secrets" middle ground.
 */
class GrantsPrintCommand extends Command
{
    protected $signature = 'mcp:grants:print
        {--host=127.0.0.1 : MySQL host pattern for the created users (Channel A is local; use % as a deliberate opt-in)}
        {--ro-mode=per-table : mcp_ro read grant: "per-table" (DB-level secret exclusion, §13.7) or "schema" (GRANT db.*, blocklist-only)}';

    protected $description = 'Print the CREATE USER / GRANT statements required by the MCP MySQL accounts.';

    public function handle(GrantPlanner $planner): int
    {
        $db = (string) (config('mcp.db.database') ?? 'your_database');
        $host = (string) $this->option('host');
        $ctl = (string) (config('mcp.db.control.username') ?? 'mcp_ctl');
        $ro = (string) (config('mcp.db.read.username') ?? 'mcp_ro');
        $mode = (string) $this->option('ro-mode');

        if (! in_array($mode, ['per-table', 'schema'], true)) {
            $this->components->error("Unknown --ro-mode '{$mode}'. Use 'per-table' or 'schema'.");

            return self::FAILURE;
        }

        $tables = $planner->tableNames();

        if ($mode === 'per-table' && $tables === null) {
            $this->components->error('per-table mode needs a reachable database to list business tables.');
            $this->line('Run after migrations with the DB up, or use <fg=cyan>--ro-mode=schema</> (blocklist-only).');

            return self::FAILURE;
        }

        $this->line('-- ============================================================');
        $this->line("-- decocode/laravel-mcp — MySQL users & grants for `{$db}`");
        $this->line("-- Replace <password> before running. Adjust '{$host}' host pattern to your topology.");
        $this->line('-- ============================================================');
        $this->newLine();

        $this->line('-- Control-plane: only MCP + Passport tables (NEVER business data)');
        $this->line("CREATE USER '{$ctl}'@'{$host}' IDENTIFIED BY '<password>';");
        foreach (array_merge(GrantPlanner::CONTROL_TABLES, $planner->oauthTables($tables)) as $t) {
            $this->line("GRANT SELECT, INSERT, UPDATE, DELETE ON `{$planner->ident($db)}`.`{$planner->ident($t)}` TO '{$ctl}'@'{$host}';");
        }
        $this->newLine();

        $this->line("CREATE USER '{$ro}'@'{$host}' IDENTIFIED BY '<password>';");

        if ($mode === 'schema') {
            $this->components->warn('schema mode: mcp_ro gets DB-level SELECT on ALL tables, incl. auth/token/session — NOT for high-PII / pilot. Use --ro-mode=per-table.');
            $this->line('-- Data-plane READ (schema mode): SELECT on the WHOLE DB — including auth/token/');
            $this->line('-- session tables (oauth_*, sessions, personal_access_tokens). The NEVER_READ');
            $this->line('-- floor and secret exclusion are BYPASSED at the DB level here; only the');
            $this->line('-- app-level blocklist/masking protect them. Does NOT meet DoD §13.7 —');
            $this->line('-- use --ro-mode=per-table for high-PII / pilot.');
            $this->line("GRANT SELECT ON `{$planner->ident($db)}`.* TO '{$ro}'@'{$host}';");
        } else {
            /** @var list<string> $business */
            $business = $planner->businessTables($tables);

            $this->line('-- Data-plane READ (per-table mode): SELECT only on business tables; secret');
            $this->line('-- tables are excluded at the DB level (§13.7), mirroring the app blocklist.');
            $this->line('-- After adding business tables, run `php artisan mcp:grants:diff` for just the new grants.');

            if ($business === []) {
                $this->line("-- (No business tables found for `{$db}`.)");
            }

            foreach ($business as $t) {
                $this->line("GRANT SELECT ON `{$planner->ident($db)}`.`{$planner->ident($t)}` TO '{$ro}'@'{$host}';");
            }
        }
        $this->newLine();

        $this->line('-- Data-plane WRITE (mcp_rw): create ONLY when enabling write capability.');
        $this->line("-- CREATE USER 'mcp_rw'@'{$host}' IDENTIFIED BY '<password>';");
        $this->line("-- GRANT SELECT, INSERT, UPDATE ON `{$planner->ident($db)}`.* TO 'mcp_rw'@'{$host}';  -- NO DELETE, NO DDL");
        $this->newLine();

        $this->line('FLUSH PRIVILEGES;');

        return self::SUCCESS;
    }
}
