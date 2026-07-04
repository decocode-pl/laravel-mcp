<?php

declare(strict_types=1);

namespace Decocode\LaravelMcp\Console;

use Decocode\LaravelMcp\Capabilities\Capability;
use Decocode\LaravelMcp\Console\Concerns\ResolvesMcpAccount;
use Decocode\LaravelMcp\Models\McpAbility;
use Illuminate\Console\Command;

class AccountGrantCommand extends Command
{
    use ResolvesMcpAccount;

    protected $signature = 'mcp:account:grant
        {account : MCP account id or name}
        {capability : One of: read, write, delete, command:run}
        {--scope=* : Optional scope values narrowing the grant}';

    protected $description = 'Grant a capability to an MCP service account.';

    public function handle(): int
    {
        $capability = (string) $this->argument('capability');

        if (! Capability::isKnown($capability)) {
            $this->components->error("Unknown capability '{$capability}'. Known: ".implode(', ', Capability::all()));

            return self::FAILURE;
        }

        $account = $this->resolveAccount((string) $this->argument('account'));

        if ($account === null) {
            $this->components->error('MCP account not found.');

            return self::FAILURE;
        }

        $scope = array_values(array_filter((array) $this->option('scope')));

        McpAbility::updateOrCreate(
            ['account_id' => $account->getKey(), 'capability' => $capability],
            ['scope' => $scope === [] ? null : $scope],
        );

        $this->components->info("Granted '{$capability}' to account #{$account->getKey()} ({$account->name}).");

        if ($capability === Capability::DELETE && config('mcp.capabilities.delete_enabled', false) !== true) {
            $this->components->warn("Note: 'delete' is globally disabled (kill-switch). This grant stays inert until MCP_DELETE_ENABLED=true.");
        }

        return self::SUCCESS;
    }
}
