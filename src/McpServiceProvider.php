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
use Decocode\LaravelMcp\Security\ColumnMasker;
use Decocode\LaravelMcp\Security\TableBlocklist;
use Decocode\LaravelMcp\Support\ConnectionRegistrar;
use Illuminate\Support\ServiceProvider;

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

        // IP allowlist guard for the MCP web route (see routes/ai.php snippet in the README).
        $this->app['router']->aliasMiddleware('mcp.ip-allowlist', EnsureIpAllowed::class);

        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../config/mcp.php' => config_path('mcp.php'),
            ], 'mcp-config');

            $this->publishes([
                __DIR__.'/../database/migrations' => database_path('migrations'),
            ], 'mcp-migrations');

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
}
