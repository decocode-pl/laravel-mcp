<?php

declare(strict_types=1);

namespace Decocode\LaravelMcp\Capabilities;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * Resolves whether an authenticated MCP identity may exercise a capability.
 * Interface so the storage backend can be swapped without touching callers.
 */
interface CapabilityResolver
{
    public function allows(?Authenticatable $account, string $capability, ?string $scope = null): bool;
}
