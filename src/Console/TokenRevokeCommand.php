<?php

declare(strict_types=1);

namespace Decocode\LaravelMcp\Console;

use Decocode\LaravelMcp\Console\Concerns\ResolvesMcpAccount;
use Illuminate\Console\Command;

/**
 * Revoke access tokens issued to an MCP account — by label (default) or all of
 * them. Complements mcp:token:issue; disabling the whole account
 * (mcp:account:revoke --disable) additionally stops capability resolution.
 */
class TokenRevokeCommand extends Command
{
    use ResolvesMcpAccount;

    protected $signature = 'mcp:token:revoke
        {account : MCP account id or name}
        {--name=mcp : Revoke only tokens with this label}
        {--all : Revoke every token for the account}';

    protected $description = 'Revoke Passport access tokens for an MCP account.';

    public function handle(): int
    {
        $account = $this->resolveAccount((string) $this->argument('account'));

        if ($account === null) {
            $this->components->error('MCP account not found.');

            return self::FAILURE;
        }

        $query = $account->tokens();

        if (! $this->option('all')) {
            $query->where('name', (string) $this->option('name'));
        }

        $revoked = 0;

        foreach ($query->get() as $token) {
            $token->revoke();
            $revoked++;
        }

        $this->components->info($revoked > 0
            ? "Revoked {$revoked} token(s) for account #{$account->getKey()} ({$account->name})."
            : "No matching tokens for account #{$account->getKey()}.");

        return self::SUCCESS;
    }
}
