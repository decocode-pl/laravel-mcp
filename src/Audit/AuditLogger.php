<?php

declare(strict_types=1);

namespace Decocode\LaravelMcp\Audit;

use Illuminate\Support\Facades\DB;
use Throwable;

/**
 * Append-only audit trail on the control-plane connection. Every MCP call
 * (query / tool / command) should pass through here — production data and PII
 * flow to the model, so we record what left.
 *
 * PR-010: this layer is FAIL-CLOSED. A failure to encode the parameters
 * (invalid UTF-8) or to persist the row raises AuditException; tool callers
 * abort and return no data rather than leak an unlogged result.
 */
class AuditLogger
{
    /**
     * @param  array<string,mixed>  $parameters
     * @param  array<string,mixed>|null  $resultSummary
     */
    public function log(
        string $channel,
        string $name,
        array $parameters = [],
        ?int $accountId = null,
        ?int $rowCount = null,
        ?int $exitCode = null,
        ?string $ip = null,
        ?array $resultSummary = null,
    ): void {
        $connection = (string) config('mcp.audit.connection', 'mcp_ctl');
        $table = (string) config('mcp.audit.table', 'mcp_audit_log');

        $row = [
            'account_id' => $accountId,
            'channel' => $channel,
            'name' => $name,
            'parameters' => $this->encode($parameters),
            'result_summary' => $resultSummary === null ? null : $this->encode($resultSummary),
            'row_count' => $rowCount,
            'exit_code' => $exitCode,
            'ip' => $ip,
            'created_at' => now(),
        ];

        try {
            DB::connection($connection)->table($table)->insert($row);
        } catch (Throwable $e) {
            throw new AuditException("Failed to persist audit record for [{$channel}:{$name}].", 0, $e);
        }
    }

    /**
     * Encode audit payloads defensively. JSON_INVALID_UTF8_SUBSTITUTE keeps
     * malformed byte sequences (common in raw production data) from failing the
     * encode; if it still fails, we fail closed rather than store a broken row.
     *
     * @param  array<string,mixed>  $value
     */
    private function encode(array $value): string
    {
        $json = json_encode(
            $value,
            JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE
        );

        if ($json === false) {
            throw new AuditException('Unable to encode audit parameters: '.json_last_error_msg());
        }

        return $json;
    }
}
