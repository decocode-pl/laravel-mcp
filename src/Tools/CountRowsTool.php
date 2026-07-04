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
 * Aggregate row count for a table, optionally filtered. read_query cannot
 * project functions (that would rename PII past the masker), so counting lives
 * here instead: the projection is FIXED to `COUNT(*)` by us — the caller only
 * chooses the table and an optional WHERE fragment — so the result is always a
 * single integer and no column value is ever surfaced.
 *
 * Guards: the table must be a plain identifier and not blocklisted; the fully
 * assembled query passes QueryGuard::validate (SELECT-only, single statement,
 * no INTO OUTFILE, no comment injection) and the blocklist scan (so a blocked
 * table cannot be reached through the WHERE fragment either).
 *
 * To blunt the count-as-oracle risk on PII, the WHERE fragment may not
 * reference a masked column (`WHERE pesel LIKE '44%'` is refused) — so a
 * sensitive value cannot be extracted bit-by-bit through the count. Filtering
 * on ordinary columns (status, created_at, …) is unaffected.
 */
class CountRowsTool extends AbstractDiagnosticTool
{
    protected string $name = 'count_rows';

    protected string $description = 'Count rows in a table, optionally filtered by a WHERE condition '
        .'(which may not reference masked columns). Returns only an aggregate integer — never row data.';

    public function __construct(
        private QueryGuard $guard,
        private TableBlocklist $blocklist,
        private ColumnMasker $masker,
    ) {}

    public function schema(JsonSchema $schema): array
    {
        return [
            'table' => $schema->string()->required()
                ->description('Table to count (a plain identifier).'),
            'where' => $schema->string()
                ->description('Optional SQL boolean condition, without the WHERE keyword.'),
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
            'table' => ['required', 'string'],
            'where' => ['nullable', 'string'],
        ]);

        $table = (string) $validated['table'];
        $where = trim((string) ($validated['where'] ?? ''));

        // The table is interpolated (not a binding), so it must be a bare identifier.
        if (preg_match('/^[a-zA-Z0-9_]+$/', $table) !== 1) {
            throw new QueryGuardException('Table must be a plain identifier.');
        }

        if ($this->blocklist->isBlocked($table)) {
            throw new QueryGuardException("Table [{$table}] is blocked from MCP access.");
        }

        // Reject set operations in the WHERE fragment — they would append another
        // query to the count (harmless here, but inconsistent with read_query and
        // an unnecessary surface). Strip single-quoted literals first so a value
        // like 'union dues' is not mistaken for the keyword.
        $whereScan = (string) preg_replace('/\'(?:[^\'\\\\]|\\\\.)*\'/', "''", $where);
        if ($where !== '' && preg_match('/\b(union|intersect|except)\b/i', $whereScan) === 1) {
            throw new QueryGuardException('Set operations are not allowed in the WHERE condition.');
        }

        // A count filtered on a masked column would be an existence oracle for
        // that PII (`WHERE pesel LIKE '44%'`). Refuse any masked-column reference.
        if ($where !== '') {
            preg_match_all('/[a-z_][a-z0-9_]*/i', $whereScan, $identifiers);

            foreach (array_unique($identifiers[0]) as $identifier) {
                if ($this->masker->shouldMask($identifier)) {
                    throw new QueryGuardException("The WHERE condition may not reference the masked column [{$identifier}].");
                }
            }
        }

        $sql = "SELECT COUNT(*) AS aggregate FROM `{$table}`"
            .($where !== '' ? " WHERE {$where}" : '');

        // Validate the assembled query (SELECT-only, single statement, no exfiltration).
        $this->guard->validate($sql);

        if (($blocked = $this->blocklist->firstBlockedReference($sql)) !== null) {
            throw new QueryGuardException("Reference to a blocked table [{$blocked}] is not allowed.");
        }

        $connection = (string) config('mcp.read.connection', 'mcp_ro');
        $this->applyReadTimeout($connection);

        $count = (int) (DB::connection($connection)->selectOne($sql)->aggregate ?? 0);

        return [
            'payload' => ['table' => $table, 'count' => $count],
            'row_count' => $count,
            'audit_params' => ['table' => $table, 'where' => $where],
        ];
    }
}
