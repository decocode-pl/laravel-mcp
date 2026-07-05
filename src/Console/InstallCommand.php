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
    protected $signature = 'mcp:install {--with-oauth : Also scaffold channel B (claude.ai OAuth): publish the consent view and print the operator-gate steps.}';

    protected $description = 'Install decocode/laravel-mcp: publish config & migrations, run migrations, print required manual steps.';

    public function handle(): int
    {
        $withOauth = (bool) $this->option('with-oauth');

        $this->components->info('Publishing MCP config and migrations…');
        $this->callSilent('vendor:publish', ['--tag' => 'mcp-config']);
        $this->callSilent('vendor:publish', ['--tag' => 'mcp-migrations']);

        if ($withOauth) {
            $this->components->info('Publishing channel B consent view…');
            $this->callSilent('vendor:publish', ['--tag' => 'mcp-oauth-views']);
        }

        $this->components->info('Running MCP migrations…');
        $this->components->warn('Note: this runs ALL pending application migrations, not just the package\'s.');
        $this->call('migrate');

        $this->newLine();
        $this->components->warn('Manual steps required — apply and verify these yourself:');
        $this->newLine();

        $this->line('  1) config/auth.php — add the dedicated MCP guard (leaves existing guards untouched):');
        $this->line($this->authSnippet($withOauth));
        $this->newLine();

        $this->line('  2) routes/ai.php — register the OAuth + MCP web routes:');
        $this->line($this->routesSnippet());
        $this->newLine();

        $this->line('  3) Provision the MySQL users and grants:  <fg=cyan>php artisan mcp:grants:print</>');
        $this->line('  4) Install Passport (keys + personal access client for Bearer tokens):  <fg=cyan>php artisan passport:install</>');
        $this->newLine();

        if ($withOauth) {
            $this->printChannelBSteps();
        }

        $this->components->info('Then:');
        $this->line('  • Create an account:            <fg=cyan>php artisan mcp:account:create <name></>');
        $this->line('  • Grant it read:                <fg=cyan>php artisan mcp:account:grant <name> read</>');
        $this->line('  • Issue a Claude Code token:    <fg=cyan>php artisan mcp:token:issue <name></>');

        if ($withOauth) {
            $this->newLine();
            $this->line('  • Point <fg=cyan>mcp.oauth.account</> at that account name, set <fg=cyan>MCP_HTTP_ENABLED=true</>,');
            $this->line('    and expose the app over HTTPS (a dedicated domain or a tunnel).');
        }

        return self::SUCCESS;
    }

    /**
     * Print the channel-B (claude.ai OAuth) wiring: the session guard, the operator
     * middleware, and the one project-specific hook (who may authorize a connector).
     */
    private function printChannelBSteps(): void
    {
        $this->components->warn('Channel B (claude.ai OAuth) — additional wiring:');
        $this->newLine();

        $this->line('  5) config/passport.php — resolve Passport against the MCP session guard');
        $this->line('     (only when Passport is used SOLELY for MCP): <fg=cyan>\'guard\' => \'mcp_web\'</>');
        $this->newLine();

        $this->line('  6) bootstrap/app.php — add the operator gate to the `web` middleware group:');
        $this->line($this->operatorMiddlewareSnippet());
        $this->newLine();

        $this->line('  7) Answer "who may authorize a connector" — pick ONE:');
        $this->line($this->operatorHookSnippet());
        $this->newLine();

        $this->components->warn('Channel B prerequisites (hard requirements):');
        $this->line('  • Passport must be dedicated to MCP in this app: setting <fg=cyan>passport.guard=mcp_web</>');
        $this->line('    is GLOBAL — with it the token `sub` is the service account; without it the token');
        $this->line('    resource owner becomes the human operator. Do NOT enable channel B in an app that');
        $this->line('    uses Passport for its own OAuth unless you have separated them.');
        $this->line('  • The Passport authorize route must run in the `web` middleware group (the default),');
        $this->line('    or the operator gate never fires.');
        $this->newLine();
    }

    private function authSnippet(bool $withOauth = false): string
    {
        $webGuard = $withOauth ? <<<'PHP'

        // channel B (claude.ai OAuth): session guard the service account is logged
        // into as the OAuth resource owner.
        'mcp_web' => ['driver' => 'session', 'provider' => 'mcp_service'],
        PHP : '';

        return <<<PHP
        // 'guards' =>
        'mcp' => ['driver' => 'passport', 'provider' => 'mcp_service'],{$webGuard}

        // 'providers' =>
        'mcp_service' => [
            'driver' => 'eloquent',
            'model'  => \\Decocode\\LaravelMcp\\Models\\McpServiceAccount::class,
        ],
        PHP;
    }

    private function operatorMiddlewareSnippet(): string
    {
        return <<<'PHP'
        // ->withMiddleware(function (Middleware $middleware) {
        $middleware->web(append: [\Decocode\LaravelMcp\Http\Middleware\EnsureMcpOperator::class]);
        PHP;
    }

    private function operatorHookSnippet(): string
    {
        return <<<'PHP'
        // (a) a Gate ability — the simple path. In a service provider:
        //     Gate::define('mcp-operator', fn ($u) => $u->hasRole('Super Admin'));
        //     config/mcp.php:  'operator_guard' => 'web', 'operator_gate' => 'mcp-operator'
        //
        // (b) an McpOperatorCheck class — for logic a Gate can't express:
        //     config/mcp.php:  'operator_check' => \App\Mcp\SuperAdminOperator::class
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
