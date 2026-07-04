<?php

declare(strict_types=1);

namespace Decocode\LaravelMcp\Console;

use Decocode\LaravelMcp\Models\McpServiceAccount;
use Illuminate\Console\Command;

class AccountCreateCommand extends Command
{
    protected $signature = 'mcp:account:create {name : Human-readable identifier for the MCP account} {--description=}';

    protected $description = 'Create a new MCP service account (control-plane).';

    public function handle(): int
    {
        $account = McpServiceAccount::create([
            'name' => (string) $this->argument('name'),
            'description' => $this->option('description'),
        ]);

        $this->components->info("MCP account created: #{$account->getKey()} ({$account->name}).");
        $this->line('Grant capabilities with:  <fg=cyan>php artisan mcp:account:grant '.$account->getKey().' read</>');

        return self::SUCCESS;
    }
}
