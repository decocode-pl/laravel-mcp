<?php

declare(strict_types=1);

namespace Decocode\LaravelMcp\Tools;

use Decocode\LaravelMcp\Capabilities\Capability;
use Decocode\LaravelMcp\Security\ColumnMasker;
use Decocode\LaravelMcp\Security\TableBlocklist;
use Decocode\LaravelMcp\Support\GrantPlanner;
use Illuminate\Contracts\JsonSchema\JsonSchema;
use Illuminate\Support\Facades\Schema;
use Laravel\Mcp\Request;

/**
 * Schema introspection over the read connection. Respects both read-restriction
 * layers: blocked tables are never listed or described, and each column is
 * flagged with whether its VALUES would be masked — the schema itself carries
 * no data, so no PII is exposed here.
 */
class SchemaDescribeTool extends AbstractDiagnosticTool
{
    protected string $name = 'schema_describe';

    protected string $description = 'Describe the database schema: list tables, or the columns of one table. '
        .'Blocked tables are hidden; each column notes whether its values are masked. No row data is returned.';

    public function __construct(
        private TableBlocklist $blocklist,
        private ColumnMasker $masker,
    ) {}

    public function schema(JsonSchema $schema): array
    {
        return [
            'table' => $schema->string()
                ->description('Optional table name. Omit to list all readable tables.'),
        ];
    }

    protected function capability(): string
    {
        return Capability::READ;
    }

    protected function channel(): string
    {
        return 'tool';
    }

    protected function run(Request $request): array
    {
        $validated = $request->validate([
            'table' => ['nullable', 'string'],
        ]);

        $connection = (string) config('mcp.read.connection', 'mcp_ro');
        $table = $validated['table'] ?? null;

        return $table === null
            ? $this->listTables($connection)
            : $this->describeTable($connection, (string) $table);
    }

    /**
     * @return array<string,mixed>
     */
    private function listTables(string $connection): array
    {
        // Scope to the target database — getTables() with no schema returns
        // tables from every database the connection can see.
        $tables = collect(Schema::connection($connection)->getTables(GrantPlanner::targetSchema()))
            ->map(fn (array $t): string => (string) $t['name'])
            ->reject(fn (string $name): bool => $this->blocklist->isBlocked($name))
            ->sort()
            ->values()
            ->all();

        return [
            'payload' => ['tables' => $tables],
            'row_count' => count($tables),
            'audit_params' => ['action' => 'list_tables'],
        ];
    }

    /**
     * @return array<string,mixed>
     */
    private function describeTable(string $connection, string $table): array
    {
        if ($this->blocklist->isBlocked($table)) {
            return [
                'payload' => ['error' => "Table [{$table}] is blocked from MCP access."],
                'audit_params' => ['action' => 'describe', 'table' => $table, 'blocked' => true],
            ];
        }

        $columns = array_map(function (array $column) use ($table): array {
            $name = (string) $column['name'];

            return [
                'name' => $name,
                'type' => (string) ($column['type'] ?? $column['type_name'] ?? ''),
                'nullable' => (bool) ($column['nullable'] ?? false),
                // Table-qualified (0.3.0): the described table is known, so
                // per-table rules are reflected in the reported mask flag.
                'masked' => $this->masker->shouldMask($name, $table),
            ];
        }, Schema::connection($connection)->getColumns($table));

        return [
            'payload' => ['table' => $table, 'columns' => $columns],
            'row_count' => count($columns),
            'audit_params' => ['action' => 'describe', 'table' => $table],
        ];
    }
}
