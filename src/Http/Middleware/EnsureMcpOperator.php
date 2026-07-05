<?php

declare(strict_types=1);

namespace Decocode\LaravelMcp\Http\Middleware;

use Closure;
use Decocode\LaravelMcp\Contracts\McpOperatorCheck;
use Decocode\LaravelMcp\Models\McpServiceAccount;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Route;
use Symfony\Component\HttpFoundation\Response;

/**
 * Human gate for the MCP OAuth consent endpoint (channel B, claude.ai).
 *
 * /oauth/authorize is a public route, so it must not hand out tokens freely. This
 * middleware (alias `mcp.operator`, register it in the `web` group) lets only an
 * authorized operator connect a client, then logs the read-only service account in
 * as the OAuth resource owner — its id becomes the token `sub`, which is exactly
 * what the `mcp` guard resolves via the mcp_service provider. Any non-authorize
 * request passes straight through untouched.
 *
 * "Who is an operator" is the one project-specific decision — answer it with a Gate
 * ability (`mcp.oauth.operator_gate`) or an McpOperatorCheck class
 * (`mcp.oauth.operator_check`, which wins when set). See config/mcp.php.
 */
class EnsureMcpOperator
{
    public function handle(Request $request, Closure $next): Response
    {
        // Passport names its authorize route `passport.authorizations.authorize`.
        if (! $request->routeIs('passport.authorizations.authorize')) {
            return $next($request);
        }

        $accountId = $this->authorizeOperator($request);

        // Security boundary: an authorization code may only ever be delivered to an
        // allowlisted (claude.ai) redirect. Client registration is public, so without
        // this a crafted client with an attacker-controlled redirect_uri could receive
        // a code. (The consent screen — always shown, never auto-approved — is the
        // other half of the phishing defence.)
        $redirect = (string) $request->query('redirect_uri', '');
        if (! in_array($redirect, (array) config('mcp.oauth.redirect_allowlist', []), true)) {
            abort(Response::HTTP_FORBIDDEN, 'MCP: disallowed OAuth client redirect_uri.');
        }

        // Resource owner for the issued token = the read-only service account. A
        // revoked account is treated as absent — never mint a live token for an
        // identity marked revoked.
        $account = $accountId !== null
            ? McpServiceAccount::query()->whereNull('revoked_at')->find($accountId)
            : McpServiceAccount::query()->whereNull('revoked_at')->where('name', config('mcp.oauth.account'))->first();

        if ($account === null) {
            abort(
                Response::HTTP_INTERNAL_SERVER_ERROR,
                'MCP: OAuth service account is not provisioned (or is revoked) — create it: '
                .'php artisan mcp:account:create <name> && php artisan mcp:account:grant <name> read.'
            );
        }

        // Force the consent screen on EVERY authorize, never auto-approve. Passport
        // skips consent when the resource owner already granted this client+scope
        // (skipsAuthorization / hasGrantedScopes) unless `prompt=consent` is present.
        // The resource owner is a SHARED service account, so a persisted grant would
        // otherwise let a later flow — a client reusing a stable client_id — mint a
        // token with NO human seeing the anti-phishing warning. Setting prompt=consent
        // makes Passport's skip condition (`$prompt->doesntContain('consent') && …`)
        // false, so both shortcuts are disabled.
        $request->merge(['prompt' => 'consent']);
        $request->query->set('prompt', 'consent');

        Auth::guard(config('mcp.oauth.web_guard', 'mcp_web'))->loginUsingId($account->getKey());

        return $next($request);
    }

    /**
     * Run the operator hook. Returns the service-account id to use as resource owner
     * (null = fall back to config('mcp.oauth.account')). Aborts/redirects on failure.
     */
    private function authorizeOperator(Request $request): ?int
    {
        // Advanced path: a class owns the whole decision (403 on refusal).
        $check = config('mcp.oauth.operator_check');
        if ($check !== null) {
            /** @var McpOperatorCheck $checker */
            $checker = app($check);

            if (! $checker->authorize($request)) {
                abort(Response::HTTP_FORBIDDEN, 'MCP: connecting a connector is not permitted.');
            }

            return $checker->serviceAccountId();
        }

        // Simple path: an authenticated operator on the configured guard, gated by an
        // ability. Fail closed — with NEITHER an operator_check NOR an operator_gate,
        // "who may authorize" is undefined; refuse rather than let any authenticated
        // user connect a connector to production data (a silent misconfig otherwise
        // opens channel B to every logged-in user).
        $gate = config('mcp.oauth.operator_gate');
        if ($gate === null) {
            abort(
                Response::HTTP_FORBIDDEN,
                'MCP: channel B has no operator gate — set mcp.oauth.operator_gate or mcp.oauth.operator_check.'
            );
        }

        // Unauthenticated → bounce through the app's login (honours the intended URL).
        $user = Auth::guard(config('mcp.oauth.operator_guard', 'web'))->user();
        if ($user === null) {
            abort(redirect()->guest($this->loginUrl()));
        }

        if (Gate::forUser($user)->denies($gate)) {
            abort(Response::HTTP_FORBIDDEN, 'MCP: connecting a connector requires operator privileges.');
        }

        return null;
    }

    /**
     * Resolve the login target: a route name if it exists, otherwise treat the value
     * as a path. Honours the intended URL so the operator returns to authorize.
     */
    private function loginUrl(): string
    {
        $target = (string) config('mcp.oauth.operator_login_route', 'login');

        return Route::has($target) ? route($target) : url($target);
    }
}
