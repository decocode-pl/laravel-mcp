<?php

declare(strict_types=1);

namespace Decocode\LaravelMcp\Console\Concerns;

use Decocode\LaravelMcp\Models\McpServiceAccount;

/**
 * Resolve an MCP account from a CLI argument that is either its numeric id or
 * its unique name. Shared by the account:* and token:* commands.
 */
trait ResolvesMcpAccount
{
    protected function resolveAccount(string $identifier): ?McpServiceAccount
    {
        if (ctype_digit($identifier)) {
            return McpServiceAccount::find((int) $identifier);
        }

        return McpServiceAccount::where('name', $identifier)->first();
    }
}
