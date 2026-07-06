<?php

declare(strict_types=1);

namespace Decocode\LaravelMcp\Console;

use Decocode\LaravelMcp\Security\ColumnMasker;
use Decocode\LaravelMcp\Security\PiiHeuristic;
use Decocode\LaravelMcp\Support\GrantPlanner;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Schema;
use Throwable;

/**
 * Full-schema masking audit: for every table mcp_ro may read, flag columns that
 * LOOK like PII (PiiHeuristic) but are NOT masked (ColumnMasker, table-aware).
 *
 * This is the answer to a hard lesson: reviewing masking against a diff or a
 * hand-built column list PASSES gaps a full-schema scan catches — a legacy
 * mail/phone column under a non-obvious name, `revisions.old/new`, a bare `ip`.
 * Run it as part of a deployment's Definition of Done, after tuning
 * `masking.patterns` / `masking.table_patterns` for the project's schema.
 *
 * It is a GATE, so it fails safe: a green result requires PROVEN coverage. Zero
 * readable tables, or a table that cannot be introspected, is treated as "not
 * proven clean" (never silently reported as "no gaps"). The heuristic is
 * deliberately broad — an empty result is not proof of no PII, only that no
 * suspect column slipped the current masking config.
 *
 * It only READS the schema (information_schema, MySQL-only) — never any data.
 */
class MaskingAuditCommand extends Command
{
    protected $signature = 'mcp:masking:audit
        {--json : Output machine-readable JSON instead of the report}
        {--strict : Exit non-zero when any unmasked PII-suspect column is found or a table cannot be scanned (for CI / DoD gates)}';

    protected $description = 'Scan every readable table for PII-suspect columns that are not masked (full-schema masking audit).';

    public function handle(GrantPlanner $planner, ColumnMasker $masker): int
    {
        $tables = $planner->businessTables();

        if ($tables === null) {
            $this->components->error('Cannot read the schema — run with the target database reachable (information_schema is MySQL-only).');

            return self::FAILURE;
        }

        // A gate that reports green on ZERO coverage gives false assurance — worse
        // than no gate. An empty list means the schema/grants are misconfigured
        // (e.g. mcp.db.database points at the wrong database), not "no PII".
        if ($tables === []) {
            $this->components->error('No readable tables found — check mcp.db.database and mcp_ro grants. Refusing to report a green audit on zero coverage.');

            return self::FAILURE;
        }

        /** @var array<string,list<string>> $findings */
        $findings = [];
        /** @var list<string> $skipped */
        $skipped = [];
        $scannedColumns = 0;

        foreach ($tables as $table) {
            try {
                $columns = Schema::getColumns($table);
            } catch (Throwable) {
                // A table we cannot introspect is NOT proven clean — record it so a
                // silent skip can never masquerade as "no gaps" (fails --strict).
                $skipped[] = $table;

                continue;
            }

            foreach ($columns as $column) {
                $name = (string) $column['name'];
                $scannedColumns++;

                if (PiiHeuristic::looksLikePii($name) && ! $masker->shouldMask($name, $table)) {
                    $findings[$table][] = $name;
                }
            }
        }

        return $this->option('json')
            ? $this->renderJson($findings, $skipped, count($tables), $scannedColumns)
            : $this->renderText($findings, $skipped, count($tables), $scannedColumns);
    }

    /**
     * @param  array<string,list<string>>  $findings
     * @param  list<string>  $skipped
     */
    private function renderText(array $findings, array $skipped, int $tableCount, int $columnCount): int
    {
        $db = (string) (config('mcp.db.database') ?? 'the database');

        $this->line("-- decocode/laravel-mcp — masking audit for `{$db}`");
        $this->line("-- Scanned {$tableCount} readable tables / {$columnCount} columns.");
        $this->newLine();

        if ($skipped !== []) {
            $this->components->warn(
                count($skipped).' table(s) could NOT be introspected (not proven clean): '.implode(', ', $skipped)
            );
            $this->newLine();
        }

        if ($findings === []) {
            if ($skipped === []) {
                $this->components->info("No unmasked PII-suspect columns found across {$tableCount} tables.");

                return self::SUCCESS;
            }

            // No findings, but some tables went unscanned → cannot certify clean.
            return $this->option('strict') ? self::FAILURE : self::SUCCESS;
        }

        $gapCount = array_sum(array_map('count', $findings));
        $this->components->warn(
            count($findings)." table(s) hold {$gapCount} unmasked PII-suspect column(s):"
        );
        $this->newLine();

        foreach ($findings as $table => $columns) {
            $this->line("  <fg=cyan>{$table}</>");
            foreach ($columns as $column) {
                $this->line("    - {$column}");
            }
        }

        $this->newLine();
        $this->line('These are HEURISTIC suggestions (deliberately broad — expect false positives to');
        $this->line('dismiss; an empty result is NOT proof of no PII). Confirm each: a name that looks');
        $this->line('like PII but is not (an entity `name`, a `filename`) can be ignored. Close a real');
        $this->line('gap with <fg=cyan>masking.patterns</> (everywhere) or <fg=cyan>masking.table_patterns</> (one table).');

        return $this->option('strict') ? self::FAILURE : self::SUCCESS;
    }

    /**
     * @param  array<string,list<string>>  $findings
     * @param  list<string>  $skipped
     */
    private function renderJson(array $findings, array $skipped, int $tableCount, int $columnCount): int
    {
        $this->line((string) json_encode([
            'database' => config('mcp.db.database'),
            'tables_scanned' => $tableCount,
            'columns_scanned' => $columnCount,
            'tables_skipped' => $skipped,
            'unmasked_suspect_count' => array_sum(array_map('count', $findings)),
            'findings' => $findings,
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));

        // A gate: findings OR unscanned tables both mean "not proven clean".
        return ($this->option('strict') && ($findings !== [] || $skipped !== [])) ? self::FAILURE : self::SUCCESS;
    }
}
