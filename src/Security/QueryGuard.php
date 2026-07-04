<?php

declare(strict_types=1);

namespace Decocode\LaravelMcp\Security;

/**
 * Secondary, code-level read-only guard for raw queries. The PRIMARY guarantee
 * is the SELECT-only `mcp_ro` MySQL user; this layer rejects obviously-mutating
 * SQL early and enforces a LIMIT. It is intentionally conservative (deny on
 * doubt) rather than a full SQL parser.
 */
class QueryGuard
{
    /**
     * Single-word keywords matched on word boundaries (so "created_at" /
     * "deleted_at" columns do NOT trip them) plus multi-word phrases.
     *
     * INSERT/REPLACE/TRUNCATE are deliberately absent: they collide with the
     * legit MySQL functions INSERT()/REPLACE()/TRUNCATE() inside a SELECT, and
     * their statement forms are already rejected by the start-of-statement
     * anchor below (and by the mcp_ro SELECT-only grant).
     *
     * @var list<string>
     */
    private const FORBIDDEN = [
        'update', 'delete', 'drop', 'alter', 'create',
        'grant', 'revoke', 'call', 'rename', 'handler', 'attach',
        'into outfile', 'into dumpfile', 'load_file', 'load data',
    ];

    /**
     * @var list<string>
     */
    private const ALLOWED_STARTS = ['select', 'with', 'show', 'desc', 'explain'];

    public function validate(string $sql): void
    {
        $sql = trim($this->stripComments($sql));

        if ($sql === '') {
            throw new QueryGuardException('Empty query.');
        }

        if ($this->hasMultipleStatements($sql)) {
            throw new QueryGuardException('Only a single statement is allowed.');
        }

        // Collapse whitespace so multi-word phrases like "into  outfile"
        // (padded with extra spaces/tabs/newlines) cannot slip past the matcher.
        $lower = strtolower((string) preg_replace('/\s+/', ' ', $sql));

        if (! $this->startsWithAllowed($lower)) {
            throw new QueryGuardException('Only read queries (SELECT/WITH/SHOW/DESCRIBE/EXPLAIN) are allowed.');
        }

        // Scan FORBIDDEN keywords on the SQL with string literals stripped, so a
        // legit literal value (e.g. WHERE action = 'delete') does not trip them.
        $lowerNoStrings = $this->stripStringLiterals($lower);

        foreach (self::FORBIDDEN as $keyword) {
            if ($this->containsKeyword($lowerNoStrings, $keyword)) {
                throw new QueryGuardException("Forbidden keyword detected: {$keyword}");
            }
        }
    }

    /**
     * Produce a single, ready-to-execute SQL string: comments stripped,
     * validated (throws like validate()), and an outer LIMIT enforced on the
     * comment-free, normalized version. Callers should execute THIS, never the
     * raw input.
     */
    public function sanitize(string $sql, int $max): string
    {
        $normalized = trim($this->stripComments($sql));

        $this->validate($normalized);

        return $this->enforceLimit($normalized, $max);
    }

    /**
     * Stricter guard for the raw `read_query` tool: reject anything in the
     * SELECT projection that could rename a column and so evade name-based
     * masking (`SELECT password AS x`, `SELECT password x`, expressions). This
     * is an allow-list — only `*`, `t.*`, bare `col` / `t.col` and numeric
     * literals are accepted; function calls, expressions and everything else are
     * denied on doubt (a function's MySQL auto-alias can be truncated or shaped
     * so its name no longer contains the source column, evading name masking).
     *
     * CTEs (`WITH …`), set operations and subqueries in FROM are rejected
     * outright — their projection cannot be isolated reliably without a full
     * parser. Curated domain tools, which own their projection, do not use this.
     */
    public function guardProjection(string $sql): void
    {
        $lower = strtolower((string) preg_replace(
            '/\s+/', ' ',
            $this->stripStringLiterals(trim($this->stripComments($sql)))
        ));

        if (str_starts_with($lower, 'with ') || $lower === 'with') {
            throw new QueryGuardException('CTEs (WITH) are not supported by read_query; inline them as subqueries.');
        }

        // Set operations graft a second SELECT's columns under the FIRST SELECT's
        // (innocuous) names, evading name-based masking. Reject them (any depth).
        if (preg_match('/\b(union|intersect|except)\b/', $lower) === 1) {
            throw new QueryGuardException('Set operations (UNION/INTERSECT/EXCEPT) are not allowed in read_query.');
        }

        // JSON extraction/tabulation pulls values out of a JSON column past the
        // JsonScrubber (which only masks whole JSON payloads). Reject it.
        if (preg_match('/\bjson_(extract|value|unquote|query|table)\b|->>?/', $lower) === 1) {
            throw new QueryGuardException('JSON extraction (json_extract / json_table / -> / ->>) is not allowed in read_query.');
        }

        // Derived tables / subqueries in FROM|JOIN carry their OWN projection,
        // which this guard does not inspect — an alias there (`FROM (SELECT
        // password AS x ...) t`) would rename PII past the masker. Reject them
        // (deny-on-doubt, like CTEs and set operations). Subqueries in WHERE are
        // unaffected: they don't surface columns into the result.
        if (preg_match('/\b(?:from|join)\s*\(/', $lower) === 1) {
            throw new QueryGuardException('Subqueries / derived tables in FROM are not allowed in read_query.');
        }

        // Only SELECT has a user-controlled projection to worry about.
        if (! str_starts_with($lower, 'select')) {
            return;
        }

        $projection = trim($this->extractProjection($lower));

        // Strip a leading DISTINCT / ALL modifier before inspecting items.
        $projection = (string) preg_replace('/^(distinct|all)\b\s*/', '', $projection);

        if ($projection === '') {
            throw new QueryGuardException('Empty projection.');
        }

        foreach ($this->splitTopLevel($projection) as $item) {
            $item = trim($item);

            if (! $this->isSafeProjectionItem($item)) {
                throw new QueryGuardException(
                    'Column aliasing / expressions are not allowed in read_query '
                    .'(masking keys on the result column name). Offending item: '.$item
                );
            }
        }
    }

    /**
     * Substring between the leading SELECT and the first top-level FROM
     * (paren depth 0). No FROM (e.g. `SELECT 1`) → everything after SELECT.
     */
    private function extractProjection(string $lower): string
    {
        $after = substr($lower, strlen('select'));
        $depth = 0;
        $length = strlen($after);

        for ($i = 0; $i < $length; $i++) {
            $char = $after[$i];

            if ($char === '(') {
                $depth++;
            } elseif ($char === ')') {
                $depth--;
            } elseif ($depth === 0 && substr($after, $i, 5) === ' from') {
                // Boundary after FROM: space (` from `) or paren (` from(subquery)`).
                $next = $after[$i + 5] ?? ' ';

                if ($next === ' ' || $next === '(') {
                    return substr($after, 0, $i);
                }
            }
        }

        return $after;
    }

    /**
     * Split on commas that sit at paren depth 0.
     *
     * @return list<string>
     */
    private function splitTopLevel(string $projection): array
    {
        $items = [];
        $depth = 0;
        $buffer = '';
        $length = strlen($projection);

        for ($i = 0; $i < $length; $i++) {
            $char = $projection[$i];

            if ($char === '(') {
                $depth++;
            } elseif ($char === ')') {
                $depth--;
            }

            if ($char === ',' && $depth === 0) {
                $items[] = $buffer;
                $buffer = '';

                continue;
            }

            $buffer .= $char;
        }

        $items[] = $buffer;

        return $items;
    }

    private function isSafeProjectionItem(string $item): bool
    {
        // ONLY `*`, `t.*`, bare `col` / `t.col` (optionally back-ticked), or a
        // numeric literal. Function calls and expressions are deliberately
        // rejected: their result column name need not contain the source column
        // (MySQL truncates the auto-alias to 256 chars, e.g. a padded
        // `if(length('aa…250×…'), password, null)` loses the "password"
        // substring; exact-match patterns don't survive wrapping either), which
        // would rename PII past name-based masking. So a result column name
        // always maps back to a real source column the masker can see.
        $ident = '`?[a-z_][a-z0-9_$]*`?';

        return preg_match('/^(\*|'.$ident.'(\.(\*|'.$ident.'))?|\d+(\.\d+)?)$/', $item) === 1;
    }

    public function enforceLimit(string $sql, int $max): string
    {
        $sql = rtrim(trim($sql), ';');

        if (preg_match('/^\s*(show|desc|explain)/i', $sql) === 1) {
            return $sql;
        }

        // Anchor to the END so a LIMIT inside a subquery does not suppress the
        // outer cap. Matches "LIMIT n", "LIMIT a, b" and "LIMIT n OFFSET m". A
        // present LIMIT is CLAMPED to $max (not accepted as-is) — otherwise
        // `LIMIT 100000` would defeat the row cap the tool promises.
        $pattern = '/\blimit\s+(\d+)(?:\s*,\s*(\d+))?(?:\s+offset\s+(\d+))?\s*$/i';

        if (preg_match($pattern, $sql, $m) === 1) {
            if (isset($m[2]) && $m[2] !== '') {
                // LIMIT offset, count
                $replacement = 'LIMIT '.((int) $m[1]).', '.min((int) $m[2], $max);
            } else {
                // LIMIT count [OFFSET n]
                $offset = isset($m[3]) && $m[3] !== '' ? ' OFFSET '.$m[3] : '';
                $replacement = 'LIMIT '.min((int) $m[1], $max).$offset;
            }

            return rtrim((string) preg_replace($pattern, '', $sql)).' '.$replacement;
        }

        return $sql.' LIMIT '.$max;
    }

    private function startsWithAllowed(string $lower): bool
    {
        foreach (self::ALLOWED_STARTS as $start) {
            if (str_starts_with($lower, $start)) {
                return true;
            }
        }

        return false;
    }

    private function containsKeyword(string $lowerSql, string $keyword): bool
    {
        if (str_contains($keyword, ' ')) {
            return str_contains($lowerSql, $keyword);
        }

        return preg_match('/\b'.preg_quote($keyword, '/').'\b/', $lowerSql) === 1;
    }

    private function hasMultipleStatements(string $sql): bool
    {
        $withoutStrings = $this->stripStringLiterals($sql);
        $withoutTrailing = rtrim($withoutStrings, "; \t\n\r");

        return str_contains($withoutTrailing, ';');
    }

    private function stripComments(string $sql): string
    {
        $sql = preg_replace('/\/\*.*?\*\//s', ' ', $sql) ?? $sql;   // /* ... */
        $sql = preg_replace('/--[^\n]*/', ' ', $sql) ?? $sql;        // -- line
        $sql = preg_replace('/#[^\n]*/', ' ', $sql) ?? $sql;         // # line

        return $sql;
    }

    private function stripStringLiterals(string $sql): string
    {
        $sql = preg_replace("/'(?:[^'\\\\]|\\\\.)*'/", "''", $sql) ?? $sql;
        $sql = preg_replace('/"(?:[^"\\\\]|\\\\.)*"/', '""', $sql) ?? $sql;

        return $sql;
    }
}
