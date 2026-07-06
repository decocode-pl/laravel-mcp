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
        .'and sensitive columns (and nested JSON) are masked. Column aliasing is not allowed.';

    public function __construct(
        private QueryGuard $guard,
        private TableBlocklist $blocklist,
        private ColumnMasker $masker,
    ) {}

    public function schema(JsonSchema $schema): array
    {
        return [
            'sql' => $schema->string()->required()
                ->description('A single read-only statement: SELECT (no aliases/functions/CTEs/UNION/subqueries in FROM), SHOW or EXPLAIN.'),
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

        $connection = (string) config('mcp.read.connection', 'mcp_ro');
        $this->applyReadTimeout($connection);

        $rows = DB::connection($connection)->select($safeSql);

        // Table-qualified masking (0.3.0): a single-table SELECT gives maskRow the
        // source table, so per-table rules (e.g. customers.name) apply. A JOIN /
        // non-SELECT yields null and masking falls back to name-based only.
        $table = $this->guard->singleTableFrom($safeSql);

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

    private function resolveMaxRows(mixed $requested): int
    {
        $ceiling = (int) config('mcp.read.max_rows', 500);

        if ($requested === null) {
            return $ceiling;
        }

        return max(1, min((int) $requested, $ceiling));
    }

}
