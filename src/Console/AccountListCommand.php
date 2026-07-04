<?php

declare(strict_types=1);

namespace Decocode\LaravelMcp\Console;

use Decocode\LaravelMcp\Models\McpServiceAccount;
use Illuminate\Console\Command;

class AccountListCommand extends Command
{
    protected $signature = 'mcp:account:list';

    protected $description = 'List MCP service accounts and their capabilities.';

    public function handle(): int
    {
        $accounts = McpServiceAccount::query()->with('abilities')->get();

        if ($accounts->isEmpty()) {
            $this->components->warn('No MCP accounts yet. Create one with: php artisan mcp:account:create <name>');

            return self::SUCCESS;
        }

        $this->table(
            ['ID', 'Name', 'Capabilities', 'Revoked'],
            $accounts->map(fn (McpServiceAccount $a): array => [
                $a->getKey(),
                $a->name,
                $a->abilities->map(fn ($ability): string => $ability->capability
                    .(empty($ability->scope) ? '' : ' '.json_encode($ability->scope)))->implode(', ') ?: '—',
                $a->revoked_at?->toDateTimeString() ?? 'no',
            ])->all(),
        );

        return self::SUCCESS;
    }
}
