<?php

declare(strict_types=1);

namespace Decocode\LaravelMcp\Console;

use Decocode\LaravelMcp\Console\Concerns\ResolvesMcpAccount;
use Illuminate\Console\Command;
use Throwable;

/**
 * Issue a Passport personal access token for an MCP account, scoped to
 * `mcp:use`. This is the Bearer credential for Claude Code over the SSH/tunnel
 * channel; claude.ai uses the full OAuth flow against the same guard. The
 * plaintext token is printed ONCE — it is not recoverable afterwards.
 *
 * Requires Laravel Passport to be installed with a personal access client
 * (`php artisan passport:install`). Capabilities are resolved separately from
 * the mcp_abilities grants — a token only proves identity.
 */
class TokenIssueCommand extends Command
{
    use ResolvesMcpAccount;

    protected $signature = 'mcp:token:issue
        {account : MCP account id or name}
        {--name=mcp : Label stored with the token}';

    protected $description = 'Issue a Passport personal access token (scope mcp:use) for an MCP account.';

    public function handle(): int
    {
        $account = $this->resolveAccount((string) $this->argument('account'));

        if ($account === null) {
            $this->components->error('MCP account not found.');

            return self::FAILURE;
        }

        if ($account->revoked_at !== null) {
            $this->components->error("Account #{$account->getKey()} is disabled — re-enable it before issuing tokens.");

            return self::FAILURE;
        }

        if ($account->abilities()->count() === 0) {
            $this->components->warn('This account holds no capabilities yet — the token will authenticate but authorize nothing.');
        }

        try {
            $result = $account->createToken((string) $this->option('name'), ['mcp:use']);
        } catch (Throwable $e) {
            $this->components->error('Could not issue token: '.$e->getMessage());
            $this->line('Ensure Passport is installed with a personal access client:  <fg=cyan>php artisan passport:install</>');

            return self::FAILURE;
        }

        $this->components->info("Personal access token issued for #{$account->getKey()} ({$account->name}).");
        $this->newLine();
        $this->line('  <fg=yellow>Copy it now — it will not be shown again:</>');
        $this->line('  '.$result->accessToken);

        return self::SUCCESS;
    }
}
