<?php

declare(strict_types=1);

namespace Decocode\LaravelMcp\Tools;

use Decocode\LaravelMcp\Capabilities\Capability;
use Decocode\LaravelMcp\Security\ColumnMasker;
use Decocode\LaravelMcp\Security\QueryGuard;
use Decocode\LaravelMcp\Security\QueryGuardException;
use Decocode\LaravelMcp\Security\TableBlocklist;
use Illuminate\Contracts\JsonSchema\JsonSchema;
use Illuminate\Support\Facades\DB;
use Laravel\Mcp\Request;

/**
 * Ad-hoc read-only SQL against the SELECT-only `mcp_ro` connection. Every query
 * passes: QueryGuard (SELECT-only, single statement, forced LIMIT) →
 * projection guard (no aliasing, so masking cannot be evaded) → table blocklist
 * → ColumnMasker (name-based + nested-JSON scrubbing) → audit.
 *
 * The hard read-only guarantee is the DB grant, not this code; these layers are
 * defence-in-depth on top of it.
 */
class ReadQueryTool extends AbstractDiagnosticTool
{
    protected string $name = 'read_query';

    protected string $description = 'Run a read-only SQL SELECT against the production database. '
        .'Only SELECT/SHOW/EXPLAIN are allowed, a LIMIT is enforced, blocked tables are refused, '
        .'and sensitive columns (and nested JSON) are masked. Column aliasing is not allowed, and a '
        .'WHERE / ORDER BY may not reference a masked column (filter on id, status or timestamps instead).';

    public function __construct(
        private QueryGuard $guard,
        private TableBlocklist $blocklist,
        private ColumnMasker $masker,
    ) {}

    public function schema(JsonSchema $schema): array
    {
        return [
            'sql' => $schema->string()->required()
                ->description('A single-table read-only statement: SELECT (no aliases/functions/CTEs/UNION/JOINs/subqueries/window functions/DISTINCT *), SHOW or EXPLAIN. WHERE and ORDER BY may not reference a masked column, and ORDER BY must name a column (not a position).'),
            'max_rows' => $schema->integer()
                ->description('Optional row cap; clamped to the server maximum.'),
        ];
    }

    protected function capability(): string
    {
        return Capability::READ;
    }

    protected function channel(): string
    {
        return 'query';
    }

    protected function run(Request $request): array
    {
        $validated = $request->validate([
            'sql' => ['required', 'string'],
            'max_rows' => ['nullable', 'integer', 'min:1'],
        ]);

        $sql = (string) $validated['sql'];
        $max = $this->resolveMaxRows($validated['max_rows'] ?? null);

        // Validate + strip comments + enforce LIMIT first, so the checks below
        // run on comment-free SQL (a comment cannot hide a blocked table).
        $safeSql = $this->guard->sanitize($sql, $max);

        // Reject aliasing/expressions that could rename a column past the masker.
        $this->guard->guardProjection($safeSql);

        // Best-effort blocklist in code; the DB REVOKE is the hard layer.
        if (($blocked = $this->blocklist->firstBlockedReference($safeSql)) !== null) {
            throw new QueryGuardException("Reference to a blocked table [{$blocked}] is not allowed.");
        }

        // Table-qualified masking (0.3.0): a single-table SELECT gives maskRow the
        // source table, so per-table rules (e.g. customers.name) apply. guardProjection
        // has already refused any multi-table FROM, so this is non-null for every
        // SELECT that has a FROM.
        $table = $this->guard->singleTableFrom($safeSql);

        // Refuse any way a masked column could influence the result set beyond the
        // (masked) projection value — before the query reaches the database.
        $this->assertNoOracle($safeSql, $table);

        $connection = (string) config('mcp.read.connection', 'mcp_ro');
        $this->applyReadTimeout($connection);

        $rows = DB::connection($connection)->select($safeSql);

        $masked = array_map(
            fn ($row): array => $this->masker->maskRow((array) $row, $table),
            $rows
        );

        return [
            'payload' => [
                'row_count' => count($masked),
                'rows' => $masked,
            ],
            'row_count' => count($masked),
            'audit_params' => ['sql' => $safeSql],
        ];
    }

    /**
     * Refuse every path by which a masked column could shape the result set — its
     * ordering, grouping, dedup or the rows' existence — even though the column is
     * redacted in the projection. Masking hides the VALUE; these leak information
     * ABOUT it (bit-by-bit via an existence oracle, or as a cardinality/order signal).
     * Runs on $safeSql (post-sanitize) before execution, so no probe reaches the DB.
     * $table is the resolved single source table, so per-table masking is honoured.
     */
    private function assertNoOracle(string $safeSql, ?string $table): void
    {
        // WHERE / HAVING / GROUP BY / ORDER BY that names a masked column: an existence
        // or order oracle (`WHERE api_token LIKE 'ab%'`). count_rows guards its WHERE
        // the same way.
        if (($maskedRef = $this->masker->firstMaskedIdentifier(
            $this->guard->filterClauses($safeSql),
            $table
        )) !== null) {
            throw new QueryGuardException(
                "A WHERE / ORDER BY condition may not reference the masked column [{$maskedRef}] "
                .'(it would turn the result into an oracle for that value). Filter on non-masked '
                .'columns (id, status, timestamps).'
            );
        }

        // Positional ORDER BY / GROUP BY (`ORDER BY 2`) names no column, so the scan
        // above cannot see it — but MySQL still sorts by that (possibly masked)
        // projection column. Sort by an explicit column name instead.
        if ($this->guard->hasPositionalSort($safeSql)) {
            throw new QueryGuardException(
                'ORDER BY / GROUP BY by column position (e.g. `ORDER BY 2`) is not allowed — '
                .'it can sort by a masked column past the guard. Sort by an explicit column name.'
            );
        }

        // SELECT DISTINCT deduplicates by the REAL value before masking, so a masked
        // column in a DISTINCT projection leaks its cardinality via row_count (the
        // sister leak of GROUP BY).
        if (($distinctProjection = $this->guard->distinctProjection($safeSql)) !== null) {
            // `DISTINCT *` / `DISTINCT t.*` dedups on the whole row — masked columns
            // included — but `*` is not a scannable identifier, so name-matching can't
            // see it. Refuse it; list the specific non-masked columns instead.
            if (str_contains($distinctProjection, '*')) {
                throw new QueryGuardException(
                    'SELECT DISTINCT * is not allowed — it would deduplicate on masked column '
                    .'values (row_count would leak their cardinality). List the specific '
                    .'non-masked columns you need.'
                );
            }

            if (($maskedRef = $this->masker->firstMaskedIdentifier($distinctProjection, $table)) !== null) {
                throw new QueryGuardException(
                    "SELECT DISTINCT on the masked column [{$maskedRef}] is not allowed "
                    .'(row_count would reveal how many distinct values it has). Remove DISTINCT '
                    .'or select a non-masked column.'
                );
            }
        }
    }

    private function resolveMaxRows(mixed $requested): int
    {
        $ceiling = (int) config('mcp.read.max_rows', 500);

        if ($requested === null) {
            return $ceiling;
        }

        return max(1, min((int) $requested, $ceiling));
    }
}
