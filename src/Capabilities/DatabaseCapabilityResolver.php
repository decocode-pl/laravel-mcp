<?php

declare(strict_types=1);

namespace Decocode\LaravelMcp\Capabilities;

use Decocode\LaravelMcp\Models\McpServiceAccount;
use Illuminate\Contracts\Auth\Authenticatable;

/**
 * Default resolver: capabilities come from the mcp_abilities table via the
 * account model. Enforces global invariants ahead of any grant:
 *  - unknown capability  → denied
 *  - `delete` / `write`  → denied unless the matching kill-switch is explicitly on
 */
class DatabaseCapabilityResolver implements CapabilityResolver
{
    public function allows(?Authenticatable $account, string $capability, ?string $scope = null): bool
    {
        if (! Capability::isKnown($capability)) {
            return false;
        }

        if ($capability === Capability::DELETE && config('mcp.capabilities.delete_enabled', false) !== true) {
            return false;
        }

        if ($capability === Capability::WRITE && config('mcp.capabilities.write_enabled', false) !== true) {
            return false;
        }

        if (! $account instanceof McpServiceAccount) {
            return false;
        }

        return $account->hasCapability($capability, $scope);
    }
}
