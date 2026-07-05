<?php

declare(strict_types=1);

namespace Decocode\LaravelMcp;

use Decocode\LaravelMcp\Capabilities\CapabilityResolver;
use Decocode\LaravelMcp\Capabilities\DatabaseCapabilityResolver;
use Decocode\LaravelMcp\Console\AccountCreateCommand;
use Decocode\LaravelMcp\Console\AccountGrantCommand;
use Decocode\LaravelMcp\Console\AccountListCommand;
use Decocode\LaravelMcp\Console\AccountRevokeCommand;
use Decocode\LaravelMcp\Console\GrantsDiffCommand;
use Decocode\LaravelMcp\Console\GrantsPrintCommand;
use Decocode\LaravelMcp\Console\InstallCommand;
use Decocode\LaravelMcp\Console\TokenIssueCommand;
use Decocode\LaravelMcp\Console\TokenRevokeCommand;
use Decocode\LaravelMcp\Http\Middleware\EnsureIpAllowed;
use Decocode\LaravelMcp\Http\Middleware\EnsureMcpOperator;
use Decocode\LaravelMcp\Security\ColumnMasker;
use Decocode\LaravelMcp\Security\TableBlocklist;
use Decocode\LaravelMcp\Support\ConnectionRegistrar;
use Illuminate\Support\Carbon;
use Illuminate\Support\ServiceProvider;
use Laravel\Passport\Passport;

class McpServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/mcp.php', 'mcp');

        $this->app->bind(CapabilityResolver::class, DatabaseCapabilityResolver::class);

        // Security layers are config-derived; bind so tools can type-hint them.
        $this->app->bind(ColumnMasker::class, fn (): ColumnMasker => ColumnMasker::fromConfig());
        $this->app->bind(TableBlocklist::class, fn (): TableBlocklist => TableBlocklist::fromConfig());
    }

    public function boot(): void
    {
        // Register the dedicated read-only / control-plane DB connections.
        ConnectionRegistrar::register($this->app);

        $this->loadMigrationsFrom(__DIR__.'/../database/migrations');
        $this->loadViewsFrom(__DIR__.'/../resources/views', 'mcp');

        // IP allowlist guard for the MCP web route (see routes/ai.php snippet in the README).
        $this->app['router']->aliasMiddleware('mcp.ip-allowlist', EnsureIpAllowed::class);
        // Channel B operator gate for /oauth/authorize (register in the `web` group).
        $this->app['router']->aliasMiddleware('mcp.operator', EnsureMcpOperator::class);

        $this->bootChannelBPassport();

        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../config/mcp.php' => config_path('mcp.php'),
            ], 'mcp-config');

            $this->publishes([
                __DIR__.'/../database/migrations' => database_path('migrations'),
            ], 'mcp-migrations');

            $this->publishes([
                __DIR__.'/../resources/views' => resource_path('views/vendor/mcp'),
            ], 'mcp-oauth-views');

            $this->commands([
                InstallCommand::class,
                GrantsPrintCommand::class,
                GrantsDiffCommand::class,
                AccountCreateCommand::class,
                AccountListCommand::class,
                AccountGrantCommand::class,
                AccountRevokeCommand::class,
                TokenIssueCommand::class,
                TokenRevokeCommand::class,
            ]);
        }
    }

    /**
     * Configure Passport for channel B: always-shown consent screen (never
     * auto-approve) + short token lifetimes. Only runs when channel B is enabled
     * and the app hasn't opted out via `mcp.oauth.manage_passport`, so channel-A
     * only deployments and apps managing Passport themselves are untouched.
     */
    private function bootChannelBPassport(): void
    {
        if (! (bool) config('mcp.http.enabled', false)) {
            return;
        }

        // class_exists is defensive only — Passport is currently a hard dependency.
        if (! (bool) config('mcp.oauth.manage_passport', true) || ! class_exists(Passport::class)) {
            return;
        }

        // Passport injects the AuthorizationViewResponse as a method dependency on the
        // authorize controller, so the view MUST be bound or the endpoint 500s. Bind it
        // as a callback so ONLY MCP connectors (redirect on the allowlist) get the MCP
        // consent screen — any OTHER Passport client in this app keeps the default
        // authorize view, so enabling channel B doesn't hijack an app that also uses
        // Passport for its own first-party OAuth.
        $allowlist = (array) config('mcp.oauth.redirect_allowlist', []);
        Passport::authorizationView(function (array $parameters) use ($allowlist) {
            $redirect = $parameters['request']->redirect_uri ?? null;
            $view = in_array($redirect, $allowlist, true) ? 'mcp::oauth-consent' : 'passport::authorize';

            return view($view, $parameters);
        });

        // A leaked read-only MCP token should not be usable for a year (Passport's
        // default). claude.ai refreshes access tokens transparently. NOTE: these are
        // GLOBAL Passport lifetimes (all clients in the app) — channel B assumes
        // Passport is dedicated to MCP here (see the README prerequisite). NOTE(Octane):
        // now() is evaluated at boot; under Octane worker reuse freezes the expiry, so
        // move these to a per-request hook there.
        Passport::tokensExpireIn(Carbon::now()->addDays((int) config('mcp.oauth.token_ttl_days', 1)));
        Passport::refreshTokensExpireIn(Carbon::now()->addDays((int) config('mcp.oauth.refresh_ttl_days', 30)));
        Passport::personalAccessTokensExpireIn(Carbon::now()->addDays((int) config('mcp.oauth.personal_ttl_days', 90)));
    }
}
