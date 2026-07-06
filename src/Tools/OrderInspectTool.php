<?php

declare(strict_types=1);

namespace Decocode\LaravelMcp\Tools;

use Decocode\LaravelMcp\Capabilities\Capability;
use Decocode\LaravelMcp\Capabilities\CapabilityResolver;
use Decocode\LaravelMcp\Security\ColumnMasker;
use Decocode\LaravelMcp\Security\TableBlocklist;
use Illuminate\Contracts\JsonSchema\JsonSchema;
use Illuminate\Support\Facades\DB;
use Laravel\Mcp\Request;

/**
 * Example domain tool: fetch one record plus its related rows by id. It is
 * fully CONFIG-DRIVEN — the package ships no table names (the repo goes public).
 * Unless `mcp.tools.order_inspect` is configured it does not register, so it
 * carries nothing client-specific.
 *
 * Config shape:
 *   'order_inspect' => [
 *       'table'     => 'orders',
 *       'id_column' => 'id',
 *       'related'   => [
 *           ['table' => 'order_items', 'foreign_key' => 'order_id', 'limit' => 50],
 *       ],
 *   ],
 */
class OrderInspectTool extends AbstractDiagnosticTool
{
    protected string $name = 'order_inspect';

    protected string $description = 'Inspect a single order and its related rows by id (read-only, masked).';

    public function __construct(
        private TableBlocklist $blocklist,
        private ColumnMasker $masker,
    ) {}

    public function schema(JsonSchema $schema): array
    {
        return [
            'order_id' => $schema->integer()->required()->description('The order id to inspect.'),
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

    /**
     * Registers only when the caller has `read` AND the tool is configured.
     */
    public function shouldRegister(Request $request, CapabilityResolver $resolver): bool
    {
        return $this->config() !== [] && parent::shouldRegister($request, $resolver);
    }

    protected function run(Request $request): array
    {
        $validated = $request->validate([
            'order_id' => ['required', 'integer'],
        ]);

        $id = (int) $validated['order_id'];
        $config = $this->config();
        $connection = (string) config('mcp.read.connection', 'mcp_ro');
        $this->applyReadTimeout($connection);

        $table = (string) ($config['table'] ?? '');
        $idColumn = (string) ($config['id_column'] ?? 'id');

        if ($table === '' || $this->blocklist->isBlocked($table)) {
            return [
                'payload' => ['error' => 'order.inspect is not configured for a readable table.'],
                'audit_params' => ['order_id' => $id, 'misconfigured' => true],
            ];
        }

        $order = DB::connection($connection)->table($table)->where($idColumn, $id)->first();

        if ($order === null) {
            return [
                'payload' => ['order' => null, 'related' => []],
                'row_count' => 0,
                'audit_params' => ['order_id' => $id],
            ];
        }

        $related = [];
        $relatedCount = 0;

        foreach ((array) ($config['related'] ?? []) as $relation) {
            $relTable = (string) ($relation['table'] ?? '');
            $foreignKey = (string) ($relation['foreign_key'] ?? '');

            if ($relTable === '' || $foreignKey === '' || $this->blocklist->isBlocked($relTable)) {
                continue;
            }

            $limit = max(1, (int) ($relation['limit'] ?? 50));

            $rows = DB::connection($connection)->table($relTable)
                ->where($foreignKey, $id)
                ->limit($limit)
                ->get()
                ->map(fn ($row): array => $this->masker->maskRow((array) $row, $relTable))
                ->all();

            // A list (not keyed by table) so duplicate relations on the same
            // table don't overwrite each other.
            $related[] = ['table' => $relTable, 'rows' => $rows];
            $relatedCount += count($rows);
        }

        return [
            'payload' => [
                'order' => $this->masker->maskRow((array) $order, $table),
                'related' => $related,
            ],
            'row_count' => 1 + $relatedCount,
            'audit_params' => ['order_id' => $id],
        ];
    }

    /**
     * @return array<string,mixed>
     */
    private function config(): array
    {
        return (array) config('mcp.tools.order_inspect', []);
    }
}
