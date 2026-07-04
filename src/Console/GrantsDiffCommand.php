<?php

declare(strict_types=1);

namespace Decocode\LaravelMcp\Console;

use Decocode\LaravelMcp\Support\GrantPlanner;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;
use Throwable;

/**
 * Prints ONLY the missing per-table read grants — the business tables mcp_ro
 * cannot yet SELECT. Run it after adding tables so you apply one or two GRANT
 * lines instead of the whole script.
 *
 * It reads mcp_ro's own grants via `SHOW GRANTS` on the mcp_ro connection (a
 * user can always see its own grants — no admin privilege needed) and diffs
 * them against the introspected business tables. It never executes anything.
 */
class GrantsDiffCommand extends Command
{
    protected $signature = 'mcp:grants:diff
        {--host=127.0.0.1 : MySQL host pattern used in the printed GRANT statements}';

    protected $description = 'Print only the per-table read grants mcp_ro is still missing (for newly added tables).';

    public function handle(GrantPlanner $planner): int
    {
        $db = (string) (config('mcp.db.database') ?? 'your_database');
        $host = (string) $this->option('host');
        $ro = (string) (config('mcp.db.read.username') ?? 'mcp_ro');
        $connection = (string) config('mcp.read.connection', 'mcp_ro');

        $business = $planner->businessTables();

        if ($business === null) {
            $this->components->error('Cannot list business tables — is the database reachable?');

            return self::FAILURE;
        }

        try {
            $rows = DB::connection($connection)->select('SHOW GRANTS');
        } catch (Throwable $e) {
            $this->components->error("Could not read {$ro} grants over connection [{$connection}]: {$e->getMessage()}");
            $this->line('Ensure the mcp_ro user exists and its credentials are configured.');

            return self::FAILURE;
        }

        $granted = GrantPlanner::parseGrantedSelectTables($rows, $db);

        if ($granted['schemaWide']) {
            $this->components->warn("{$ro} holds a schema-wide SELECT on `{$db}`.* (schema mode).");
            $this->line('There is no per-table delta. To move to per-table (§13.7):');
            $this->line("  <fg=cyan>REVOKE SELECT ON `{$db}`.* FROM '{$ro}'@'{$host}';</>");
            $this->line('  then run <fg=cyan>php artisan mcp:grants:print</> and apply it.');

            return self::SUCCESS;
        }

        $missing = GrantPlanner::missing($business, $granted['tables']);

        if ($missing === []) {
            $this->line("-- {$ro} is up to date — all ".count($business).' business table(s) already granted.');

            return self::SUCCESS;
        }

        $this->line("-- Missing read grants for {$ro} (".count($missing).' new table(s)):');
        foreach ($missing as $t) {
            $this->line("GRANT SELECT ON `{$planner->ident($db)}`.`{$planner->ident($t)}` TO '{$ro}'@'{$host}';");
        }
        $this->line('FLUSH PRIVILEGES;');

        return self::SUCCESS;
    }
}
