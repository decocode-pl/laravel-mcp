<?php

declare(strict_types=1);

namespace Decocode\LaravelMcp\Console;

use Decocode\LaravelMcp\Console\Concerns\ResolvesMcpAccount;
use Illuminate\Console\Command;

class AccountRevokeCommand extends Command
{
    use ResolvesMcpAccount;

    protected $signature = 'mcp:account:revoke
        {account : MCP account id or name}
        {capability? : Capability to revoke; omit with --disable to disable the whole account}
        {--disable : Disable the entire account (sets revoked_at)}';

    protected $description = 'Revoke a capability from an MCP account, or disable the account entirely.';

    public function handle(): int
    {
        $account = $this->resolveAccount((string) $this->argument('account'));

        if ($account === null) {
            $this->components->error('MCP account not found.');

            return self::FAILURE;
        }

        if ($this->option('disable')) {
            $account->forceFill(['revoked_at' => now()])->save();
            $this->components->info("Account #{$account->getKey()} ({$account->name}) disabled.");

            return self::SUCCESS;
        }

        $capability = $this->argument('capability');

        if ($capability === null) {
            $this->components->error('Provide a capability to revoke, or use --disable to disable the account.');

            return self::FAILURE;
        }

        $deleted = $account->abilities()->where('capability', (string) $capability)->delete();

        $this->components->info($deleted > 0
            ? "Revoked '{$capability}' from account #{$account->getKey()}."
            : "Account #{$account->getKey()} did not hold '{$capability}'.");

        return self::SUCCESS;
    }
}
