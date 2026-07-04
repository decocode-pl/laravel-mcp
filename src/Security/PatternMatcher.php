<?php

declare(strict_types=1);

namespace Decocode\LaravelMcp\Security;

/**
 * Shared glob-style matcher used by the table blocklist and column masker.
 * `*` is the only wildcard (matches any run of characters). No wildcard means
 * an exact match — deliberately, so a short pattern (e.g. "nip") does not match
 * unrelated columns that merely contain it (e.g. "snippet", "manipulate").
 * For the most sensitive PII we still opt into broader `*...*` wildcards to
 * catch naming variants, and rely on the masking `allowlist` to un-mask any
 * genuine collision.
 */
final class PatternMatcher
{
    public static function matches(string $pattern, string $value): bool
    {
        if (! str_contains($pattern, '*')) {
            return $pattern === $value;
        }

        $regex = '/^'.str_replace('\*', '.*', preg_quote($pattern, '/')).'$/';

        return preg_match($regex, $value) === 1;
    }
}
