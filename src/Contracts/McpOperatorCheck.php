<?php

declare(strict_types=1);

namespace Decocode\LaravelMcp\Contracts;

use Illuminate\Http\Request;

/**
 * Optional operator hook for channel B (claude.ai OAuth).
 *
 * The `mcp.operator` middleware guards `/oauth/authorize`: it decides whether the
 * current request comes from a human allowed to connect a claude.ai connector, and
 * which read-only service account the issued token should belong to.
 *
 * Most projects answer "who may authorize" with a simple Gate ability
 * (`mcp.oauth.operator_gate`). Implement this contract only when that decision
 * needs logic a Gate can't express, or when the service account is chosen
 * dynamically. Set the implementing class in `mcp.oauth.operator_check`; it then
 * takes precedence over the gate.
 *
 * NOTE: an implementation owns the ENTIRE authorization decision — returning false
 * yields a 403. If you want an unauthenticated operator bounced to a login screen
 * instead of a 403, use the gate path (`operator_gate` + `operator_guard`), which
 * redirects to `mcp.oauth.operator_login_route`.
 */
interface McpOperatorCheck
{
    /**
     * Whether this request may authorize a channel-B connector.
     */
    public function authorize(Request $request): bool;

    /**
     * Id of the McpServiceAccount that becomes the token's resource owner (`sub`).
     * Return null to fall back to the account named in `mcp.oauth.account`.
     */
    public function serviceAccountId(): ?int;
}
