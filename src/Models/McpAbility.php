<?php

declare(strict_types=1);

namespace Decocode\LaravelMcp\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * A single capability grant for an MCP account. `capability` is keyed to the
 * capability registry (unknown = denied). `scope` (nullable JSON array) narrows
 * the grant; null/empty = unrestricted.
 */
class McpAbility extends Model
{
    protected $connection = 'mcp_ctl';

    protected $table = 'mcp_abilities';

    protected $fillable = [
        'account_id',
        'capability',
        'scope',
    ];

    protected $casts = [
        'scope' => 'array',
    ];

    public function account(): BelongsTo
    {
        return $this->belongsTo(McpServiceAccount::class, 'account_id');
    }

    public function coversScope(?string $scope): bool
    {
        // Unrestricted grant (null/empty scope) covers everything.
        if (empty($this->scope)) {
            return true;
        }

        // Scoped grant queried without a scope is fail-closed: deny.
        if ($scope === null) {
            return false;
        }

        return in_array($scope, (array) $this->scope, true);
    }
}
