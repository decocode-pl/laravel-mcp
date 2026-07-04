<?php

declare(strict_types=1);

namespace Decocode\LaravelMcp\Models;

use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Laravel\Passport\HasApiTokens;

/**
 * Dedicated MCP identity — NOT a real application user. The OAuth guard `mcp`
 * authenticates against this model; the audit log ties each call to it.
 * Capabilities are resolved from the mcp_abilities table (control-plane).
 */
class McpServiceAccount extends Authenticatable
{
    use HasApiTokens;

    protected $connection = 'mcp_ctl';

    protected $table = 'mcp_accounts';

    protected $fillable = [
        'name',
        'description',
        'revoked_at',
    ];

    protected $casts = [
        'revoked_at' => 'datetime',
    ];

    public function abilities(): HasMany
    {
        return $this->hasMany(McpAbility::class, 'account_id');
    }

    /**
     * True when this account holds the given capability for the given scope.
     * A null / empty ability scope means "unrestricted".
     */
    public function hasCapability(string $capability, ?string $scope = null): bool
    {
        if ($this->revoked_at !== null) {
            return false;
        }

        return $this->abilities()
            ->where('capability', $capability)
            ->get()
            ->contains(fn (McpAbility $ability): bool => $ability->coversScope($scope));
    }
}
