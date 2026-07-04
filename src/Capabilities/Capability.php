<?php

declare(strict_types=1);

namespace Decocode\LaravelMcp\Capabilities;

/**
 * Capability registry. Unknown capabilities are denied by construction —
 * adding a new one is a single entry here, no schema change.
 */
final class Capability
{
    public const READ = 'read';

    public const WRITE = 'write';

    public const DELETE = 'delete';

    public const COMMAND_RUN = 'command:run';

    /**
     * @return list<string>
     */
    public static function all(): array
    {
        return [self::READ, self::WRITE, self::DELETE, self::COMMAND_RUN];
    }

    public static function isKnown(string $capability): bool
    {
        return in_array($capability, self::all(), true);
    }
}
