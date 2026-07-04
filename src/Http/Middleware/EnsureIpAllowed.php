<?php

declare(strict_types=1);

namespace Decocode\LaravelMcp\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * IP allowlist for the MCP endpoint. Enabled by default and restricted to
 * local addresses (tunnel traffic terminates as 127.0.0.1). Toggle activity
 * and the allowed list via .env (MCP_IP_ALLOWLIST_ENABLED / MCP_IP_ALLOWLIST).
 */
class EnsureIpAllowed
{
    public function handle(Request $request, Closure $next): Response
    {
        $config = (array) config('mcp.ip_allowlist', []);

        if (($config['enabled'] ?? true) === true) {
            $allowed = (array) ($config['allowed'] ?? []);

            // Fail closed: an enabled allowlist with no entries is a lock-down,
            // not an open door. NOTE: $request->ip() honours the app's trusted
            // proxy config — behind a proxy, configure TrustProxies correctly so
            // X-Forwarded-For cannot be spoofed to bypass this check.
            if ($allowed === [] || ! in_array($request->ip(), $allowed, true)) {
                abort(403, 'This IP address is not allowed to reach the MCP endpoint.');
            }
        }

        return $next($request);
    }
}
