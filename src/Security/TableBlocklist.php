<?php

declare(strict_types=1);

namespace Decocode\LaravelMcp\Security;

/**
 * Layer A of the read restriction: whole tables that are never readable via
 * MCP (queries + schema introspection). Patterns support trailing/leading `*`.
 */
class TableBlocklist
{
    /**
     * @param  list<string>  $patterns
     */
    public function __construct(private array $patterns) {}

    public static function fromConfig(): self
    {
        return new self((array) config('mcp.read.blocked_tables', []));
    }

    public function isBlocked(string $table): bool
    {
        $table = strtolower($table);

        foreach ($this->patterns as $pattern) {
            if (PatternMatcher::matches(strtolower((string) $pattern), $table)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Scan EVERY identifier in a SQL string against the blocklist — not just the
     * token after FROM/JOIN — so comma-joins, subqueries and any reference style
     * are covered (a blocked table must be named to be read). Only single-quoted
     * literals are blanked (always strings in every sql_mode); double-quoted and
     * back-ticked tokens stay in, so an ANSI-quoted `"sessions"` is still caught.
     * Deny-on-doubt: an identically named column is also flagged (safe direction).
     *
     * @return string|null  the first blocked identifier, or null if none
     */
    public function firstBlockedReference(string $sql): ?string
    {
        $scrubbed = strtolower((string) preg_replace('/\'(?:[^\'\\\\]|\\\\.)*\'/', "''", $sql));

        preg_match_all('/[a-z_][a-z0-9_]*/', $scrubbed, $matches);

        foreach (array_unique($matches[0]) as $identifier) {
            if ($this->isBlocked($identifier)) {
                return $identifier;
            }
        }

        return null;
    }
}
