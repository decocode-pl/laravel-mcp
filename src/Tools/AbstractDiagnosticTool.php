<?php

declare(strict_types=1);

namespace Decocode\LaravelMcp\Tools;

use Decocode\LaravelMcp\Audit\AuditException;
use Decocode\LaravelMcp\Audit\AuditLogger;
use Decocode\LaravelMcp\Capabilities\CapabilityResolver;
use Decocode\LaravelMcp\Security\QueryGuardException;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use Laravel\Mcp\Request;
use Laravel\Mcp\Response;
use Laravel\Mcp\Server\Tool;
use Throwable;

/**
 * Shared spine for every read-only diagnostic tool:
 *  1. resolve the calling MCP identity (guard `mcp`, wired in F3);
 *  2. gate on the tool's required capability (defence-in-depth over the DB grant);
 *  3. hide the tool from callers who lack that capability (conditional registration);
 *  4. run the concrete tool logic;
 *  5. record the call to the fail-closed audit trail before any data is returned.
 *
 * Subclasses implement run() and declare their capability + audit channel.
 */
abstract class AbstractDiagnosticTool extends Tool
{
    /**
     * Capability required to see and use this tool (see Capability::*).
     */
    abstract protected function capability(): string;

    /**
     * Audit channel label (query | tool | command).
     */
    abstract protected function channel(): string;

    /**
     * Execute the tool. Return:
     *   [
     *     'payload'      => array,      // returned to the model as JSON
     *     'row_count'    => ?int,       // audited
     *     'audit_params' => array,      // what was asked (audited)
     *     'summary'      => ?array,     // optional audited result summary
     *   ]
     *
     * @return array<string,mixed>
     */
    abstract protected function run(Request $request): array;

    /**
     * Conditional registration: a caller never sees a tool beyond its grants.
     */
    public function shouldRegister(Request $request, CapabilityResolver $resolver): bool
    {
        return $resolver->allows($this->account($request), $this->capability());
    }

    public function handle(Request $request, CapabilityResolver $resolver, AuditLogger $audit): Response
    {
        $account = $this->account($request);

        // Re-check at execution time: visibility and execution are independent locks.
        if (! $resolver->allows($account, $this->capability())) {
            return Response::error('This MCP identity is not permitted to use this tool.');
        }

        try {
            $outcome = $this->run($request);
        } catch (QueryGuardException $e) {
            return Response::error('Query rejected: '.$e->getMessage());
        } catch (Throwable $e) {
            report($e);

            return Response::error('The diagnostic tool failed to run.');
        }

        // Fail-closed audit: if we cannot record what left, we return nothing.
        try {
            $audit->log(
                channel: $this->channel(),
                name: $this->name(),
                parameters: (array) ($outcome['audit_params'] ?? []),
                accountId: $account instanceof Model ? (int) $account->getKey() : null,
                rowCount: $outcome['row_count'] ?? null,
                resultSummary: $outcome['summary'] ?? null,
            );
        } catch (AuditException $e) {
            report($e);

            return Response::error('Audit logging failed; refusing to return data (fail-closed).');
        }

        return $this->json((array) ($outcome['payload'] ?? []));
    }

    /**
     * Cap statement runtime on MySQL read connections (best effort — the forced
     * LIMIT is the primary load guard; no-op on other drivers).
     */
    protected function applyReadTimeout(string $connection): void
    {
        $seconds = (int) config('mcp.read.timeout_seconds', 10);

        if ($seconds <= 0 || (string) config("database.connections.{$connection}.driver") !== 'mysql') {
            return;
        }

        try {
            DB::connection($connection)->statement('SET SESSION MAX_EXECUTION_TIME = '.($seconds * 1000));
        } catch (Throwable) {
            // Best effort.
        }
    }

    protected function account(Request $request): ?Authenticatable
    {
        $guard = (string) config('mcp.auth.guard', 'mcp');

        try {
            return $request->user($guard);
        } catch (Throwable) {
            // Guard not wired yet (pre-F3) → treat as no identity → denied.
            return null;
        }
    }

    /**
     * @param  array<string,mixed>  $payload
     */
    protected function json(array $payload): Response
    {
        $json = json_encode(
            $payload,
            JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE
        );

        return $json === false
            ? Response::error('Result could not be serialized.')
            : Response::text($json);
    }
}
