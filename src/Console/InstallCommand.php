<?php

declare(strict_types=1);

namespace Decocode\LaravelMcp\Console;

use Illuminate\Console\Command;

/**
 * Hybrid installer: automates the safe steps (publish + migrate) and PRINTS the
 * sensitive edits (auth guard, routes) so a human applies and verifies them —
 * editing config/auth.php or routes/ai.php programmatically across Laravel
 * versions is fragile and risks clobbering existing config.
 */
class InstallCommand extends Command
{
    protected $signature = 'mcp:install';

    protected $description = 'Install decocode/laravel-mcp: publish config & migrations, run migrations, print required manual steps.';

    public function handle(): int
    {
        $this->components->info('Publishing MCP config and migrations…');
        $this->callSilent('vendor:publish', ['--tag' => 'mcp-config']);
        $this->callSilent('vendor:publish', ['--tag' => 'mcp-migrations']);

        $this->components->info('Running MCP migrations…');
        $this->components->warn('Note: this runs ALL pending application migrations, not just the package\'s.');
        $this->call('migrate');

        $this->newLine();
        $this->components->warn('Manual steps required — apply and verify these yourself:');
        $this->newLine();

        $this->line('  1) config/auth.php — add the dedicated MCP guard (leaves existing guards untouched):');
        $this->line($this->authSnippet());
        $this->newLine();

        $this->line('  2) routes/ai.php — register the OAuth + MCP web routes:');
        $this->line($this->routesSnippet());
        $this->newLine();

        $this->line('  3) Provision the MySQL users and grants:  <fg=cyan>php artisan mcp:grants:print</>');
        $this->line('  4) Install Passport (keys + personal access client for Bearer tokens):  <fg=cyan>php artisan passport:install</>');
        $this->newLine();

        $this->components->info('Then:');
        $this->line('  • Create an account:            <fg=cyan>php artisan mcp:account:create <name></>');
        $this->line('  • Grant it read:                <fg=cyan>php artisan mcp:account:grant <name> read</>');
        $this->line('  • Issue a Claude Code token:    <fg=cyan>php artisan mcp:token:issue <name></>');

        return self::SUCCESS;
    }

    private function authSnippet(): string
    {
        return <<<'PHP'
        // 'guards' =>
        'mcp' => ['driver' => 'passport', 'provider' => 'mcp_service'],

        // 'providers' =>
        'mcp_service' => [
            'driver' => 'eloquent',
            'model'  => \Decocode\LaravelMcp\Models\McpServiceAccount::class,
        ],
        PHP;
    }

    private function routesSnippet(): string
    {
        return <<<'PHP'
        use Decocode\LaravelMcp\Servers\DiagnosticsServer;
        use Laravel\Mcp\Facades\Mcp;

        // Channel A (SSH/tunnel) — the DEFAULT, primary path (Claude Code, MCP Inspector):
        Mcp::local('diagnostics', DiagnosticsServer::class);

        // Channel B (public HTTPS for claude.ai) — OFF by default; enable via MCP_HTTP_ENABLED:
        Mcp::oauthRoutes();                              // claude.ai OAuth 2.1 discovery + PKCE
        Mcp::web('/mcp/diagnostics', DiagnosticsServer::class)
            ->middleware(['auth:mcp', 'mcp.ip-allowlist', 'throttle:'.config('mcp.http.throttle')]);
        PHP;
    }
}
