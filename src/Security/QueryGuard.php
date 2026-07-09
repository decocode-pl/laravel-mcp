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
        $this->assertNoExecutableComments($sql);

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
        $this->assertNoExecutableComments($sql);

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
        $this->assertNoExecutableComments($sql);

        $lower = $this->normalize($sql);

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

        // Window functions (`… OVER (…)` / `OVER w`) and the named WINDOW clause let a
        // masked column drive row ordering/partitioning from a region the oracle guard
        // does NOT scan — it only reads the WHERE/ORDER-BY tail, but
        // `WINDOW w AS (PARTITION BY password) ORDER BY SUM(id) OVER w` orders the rows
        // by the masked value from inside the WINDOW clause. A window function can also
        // live in ORDER BY, which guardProjection does not inspect for functions.
        // read_query needs no window analytics: reject the whole family (deny-on-doubt).
        // `\b` on both sides so a column like `handover`/`window_start` is not tripped.
        if (preg_match('/\bover\b|\bwindow\b/', $lower) === 1) {
            throw new QueryGuardException('Window functions (OVER / WINDOW) are not allowed in read_query.');
        }

        // Any subquery is rejected — not just in FROM (see assertNoSubquery). count_rows
        // shares this guard: it accepts a user WHERE fragment that can carry the same
        // cross-table subquery oracle.
        $this->assertNoSubquery($sql);

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

        // read_query must resolve to EXACTLY ONE source table. A JOIN, a comma-join,
        // or an unparseable/ambiguous FROM (e.g. a first table named after a clause
        // keyword — `FROM `order` JOIN …`) leaves table-qualified masking
        // (table_patterns / table_allowlist) unable to attribute columns to a table,
        // so it silently falls back to name-based masking and a column masked only
        // per-table (e.g. customers.name) leaks. Deny on doubt: if there is a FROM
        // but singleTableFrom() cannot pin it to one table, refuse — do not guess.
        // This closes the whole class (JOIN/comma/reserved-word/unparseable) with a
        // single check instead of pattern-matching each shape. count_rows and
        // order_inspect own their SQL and never reach here. Checked AFTER the
        // projection loop, which has already rejected functions/aliasing.
        if (preg_match('/\bfrom\b/', $lower) === 1 && $this->singleTableFrom($sql) === null) {
            throw new QueryGuardException(
                'read_query requires a single, unambiguous source table — JOINs, '
                .'comma-joins and multi-table FROM are not allowed (they evade '
                .'table-qualified masking). Query one table at a time, or use '
                .'count_rows / order_inspect.'
            );
        }
    }

    /**
     * Isolate the FROM clause of a normalized (comment/string-stripped, whitespace-
     * collapsed) lower-case SQL: the text after the first top-level FROM up to the
     * next clause keyword. Null when there is no FROM. Shared by guardProjection()'s
     * single-table check and singleTableFrom() so both read the same clause boundary.
     *
     * The clause-keyword split requires WHITESPACE before the keyword (`\s+`, not a
     * bare `\b`): otherwise a table named after a reserved word and back-ticked
     * (`FROM `order` JOIN …`) would split on the `order` INSIDE the back-ticks,
     * truncating the clause before the JOIN and hiding a multi-table FROM. With
     * `\s+`, a real clause keyword (always preceded by space) still ends the clause,
     * but a back-ticked table name does not.
     */
    private function fromClause(string $lower): ?string
    {
        if (preg_match('/\bfrom\s+(.+)$/s', $lower, $m) !== 1) {
            return null;
        }

        return (string) preg_split(
            '/\s+(where|group|having|order|limit|union|for|into|window)\b/',
            $m[1],
            2
        )[0];
    }

    /**
     * The filter/sort tail of a SELECT: everything from the first WHERE / GROUP /
     * HAVING / ORDER keyword to the end. This is the region where referencing a
     * masked column turns the result into an existence/order oracle
     * (`WHERE api_token LIKE 'ab%'`, `ORDER BY pesel`), so read_query scans it the
     * way count_rows scans its WHERE fragment. Returns '' when there is no such
     * clause (`SELECT * FROM t`).
     *
     * MySQL requires no whitespace to delimit a clause keyword — it is a token on its
     * own however it abuts its neighbours. A naive `\s`-anchored match leaks whenever
     * the keyword touches a non-space separator:
     *   - after the keyword: `WHERE(email LIKE 'a%')` (paren, no space)
     *   - before it: `` `users`WHERE `` (closing back-tick), `USE INDEX(x)WHERE`,
     *     `PARTITION(p)WHERE` (closing paren of a FROM suffix)
     * So BOTH boundaries are word boundaries `\b`, not `\s`: `\b` matches the edge
     * between the keyword and ANY non-word char (space, `` ` ``, `(`, `)`, `,`) or the
     * string end, closing the whole separator class in one rule rather than patching
     * one character at a time.
     *
     * Back-ticks are still replaced with spaces first (a back-ticked column in the
     * tail is then scanned as a bare identifier), and GROUP/ORDER require their `BY`,
     * so a back-ticked table named after a clause keyword (`` `order` ``) is not read
     * as one. WHERE/HAVING have no BY; a table literally named `where` would only
     * widen the scanned tail (deny-on-doubt, never narrower).
     *
     * Operates on comment/string-stripped SQL, so a literal like
     * `WHERE note = 'order by x'` is not mistaken for a clause. LIMIT / OFFSET are
     * excluded: enforceLimit guarantees they carry only integers.
     */
    /**
     * Reject any subquery `(SELECT …)` anywhere in the SQL. A subquery in FROM carries
     * its own uninspected projection (`FROM (SELECT password AS x …) t` renames PII past
     * the masker); a subquery in a WHERE fragment queries ANOTHER table, but the oracle
     * guard resolves masking under the OUTER/counted table, so a per-table masked column
     * (`customers.name` inside a subquery over `orders`) slips past and the row count
     * becomes an oracle for it. Both read_query (via guardProjection) and count_rows
     * (whose user WHERE fragment could smuggle one) share this. Scans string-literal-
     * stripped SQL, so a literal `'(select …)'` value does not trip it.
     */
    public function assertNoSubquery(string $sql): void
    {
        if (preg_match('/\(\s*select\b/', $this->normalize($sql)) === 1) {
            throw new QueryGuardException('Subqueries are not allowed; query one table at a time.');
        }
    }

    public function filterClauses(string $sql): string
    {
        $lower = $this->normalize($sql, neutralizeBackticks: true);

        if (preg_match('/\b(where|having|group\s+by|order\s+by)\b.*$/s', $lower, $m) === 1) {
            return trim($m[0]);
        }

        return '';
    }

    /**
     * The projection of a `SELECT DISTINCT …` (the DISTINCT modifier stripped), or
     * null when the query is not DISTINCT. DISTINCT deduplicates rows by the REAL
     * column value before masking, so a masked column in a DISTINCT projection is a
     * cardinality oracle: `SELECT DISTINCT password FROM users` returns one row per
     * distinct secret, so row_count leaks how many distinct values exist (and, filtered
     * by a non-masked WHERE, their distribution). This is the same leak that
     * `GROUP BY <masked>` already refuses via filterClauses — DISTINCT is the sister
     * path, so read_query scans this projection through the oracle guard too. A plain
     * (non-DISTINCT) projection is safe: row_count is the table size, independent of
     * the masked value, and each row is masked individually.
     */
    public function distinctProjection(string $sql): ?string
    {
        $lower = $this->normalize($sql);

        if (! str_starts_with($lower, 'select ')) {
            return null;
        }

        $projection = trim($this->extractProjection($lower));

        if (preg_match('/^distinct\b\s*/', $projection) !== 1) {
            return null;
        }

        return (string) preg_replace('/^distinct\b\s*/', '', $projection);
    }

    /**
     * True when an ORDER BY / GROUP BY sorts by a projection POSITION (`ORDER BY 2`)
     * instead of a column name. A positional reference names no column, so the
     * name-based oracle guard (firstMaskedIdentifier scans identifiers, not digits)
     * cannot see it — yet MySQL still orders/groups by the real, possibly masked
     * column, leaking its ordering. read_query refuses positional sorts
     * (deny-on-doubt); sort by an explicit column name, which the oracle guard can
     * vet. Operates on the same normalized, back-tick-neutralised SQL as
     * filterClauses. Each ORDER/GROUP BY clause is isolated up to the next clause
     * keyword (so a `LIMIT 2` is never mistaken for a position), split on commas,
     * and any bare-integer term (optionally ASC/DESC) trips it.
     */
    public function hasPositionalSort(string $sql): bool
    {
        $lower = $this->normalize($sql, neutralizeBackticks: true);

        if (preg_match_all(
            '/\b(?:order|group)\s+by\s+(.+?)(?=\s+(?:where|having|order\s+by|group\s+by|limit|offset|for|into|window)\b|$)/',
            $lower,
            $clauses
        ) === 0) {
            return false;
        }

        foreach ($clauses[1] as $clause) {
            foreach (explode(',', $clause) as $term) {
                $term = trim((string) preg_replace('/\s+(asc|desc)$/', '', trim($term)));

                if ($term !== '' && ctype_digit($term)) {
                    return true;
                }
            }
        }

        return false;
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

    /**
     * The single source table of a plain SELECT, for table-qualified masking
     * (0.3.0). Returns null — deny-on-doubt — for anything that is not
     * unambiguously one table: non-SELECT, a JOIN or comma-join (the flat result
     * mixes columns whose origin table we cannot tell apart), or an unparseable
     * FROM. A null result means masking falls back to the name-based layers,
     * i.e. exactly the pre-0.3.0 behaviour — never worse.
     *
     * Assumes guardProjection() has already run (read_query does), which rejects
     * CTEs, set operations and subqueries in FROM and restricts the projection to
     * bare identifiers / `*`, so the first top-level `from` is the real one and
     * no function like `substring(x FROM y)` can appear in the projection.
     *
     * A back-ticked table named after a clause keyword (`` `order` ``, `` `group` ``)
     * resolves correctly: fromClause() splits on a clause keyword only when it is
     * preceded by whitespace, so a back-ticked table name is not mistaken for the
     * clause it shares a name with (this closed PR-001, where such a name let a
     * JOIN slip past the single-table check). read_query's guardProjection() treats
     * a null here as deny-on-doubt and refuses the query rather than falling back.
     */
    public function singleTableFrom(string $sql): ?string
    {
        $lower = $this->normalize($sql);

        // Only a plain SELECT surfaces row data that maskRow() will process.
        if (! str_starts_with($lower, 'select ')) {
            return null;
        }

        $clause = $this->fromClause($lower);

        if ($clause === null) {
            return null;
        }

        // A JOIN (every flavour spells `join`; `straight_join` hides it after an
        // underscore, so match it explicitly) or a comma-join means more than one
        // table — the flat result mixes columns we cannot attribute to one table →
        // null. read_query already rejects these in guardProjection(); this stays
        // as defence-in-depth for any other caller.
        if (preg_match('/\bjoin\b|\bstraight_join\b/', $clause) === 1 || str_contains($clause, ',')) {
            return null;
        }

        // First identifier = the table (optionally `db.table`, optionally
        // back-ticked); a trailing token is an alias we ignore.
        if (preg_match('/^\s*`?([a-z_][a-z0-9_$]*)`?(?:\.`?([a-z_][a-z0-9_$]*)`?)?/', $clause, $t) !== 1) {
            return null;
        }

        // `db.table` → the table part; otherwise the sole identifier.
        return ($t[2] ?? '') !== '' ? $t[2] : $t[1];
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

    /**
     * MySQL "executable comments" — opened with the bang marker (slash-star-bang,
     * optionally version-gated like `50000`) — are EXECUTED by the server but
     * silently removed by stripComments(), so a JOIN, a forbidden keyword or a set
     * operation hidden inside one would run while every downstream check sees clean,
     * single-table SQL. Example: `SELECT * FROM orders o` then a bang-comment holding
     * `JOIN customers c ON ...` reads as one table here, but MySQL joins customers and
     * leaks its PII past table-qualified masking. Reject the marker outright —
     * read_query never needs version-gated SQL. Scans the RAW bytes, before any
     * stripComments() — and WITHOUT stripping string literals first: literal
     * stripping assumes backslash escaping, but under sql_mode=NO_BACKSLASH_ESCAPES
     * MySQL pairs quotes differently, so a crafted literal could hide the marker
     * from the stripper yet have MySQL execute it (SECURITY-002). A raw byte scan
     * closes that regardless of quote pairing; a legitimate value literally
     * containing the marker is vanishingly rare in diagnostic SELECTs, so
     * deny-on-doubt is the safe trade.
     */
    private function assertNoExecutableComments(string $rawSql): void
    {
        if (str_contains($rawSql, '/*!')) {
            throw new QueryGuardException('MySQL executable comments are not allowed in read_query.');
        }
    }

    /**
     * The shared normal form the clause/projection scanners read: comments stripped,
     * string literals blanked, whitespace collapsed to single spaces, lower-cased.
     * `$neutralizeBackticks` additionally turns back-ticks into spaces so a keyword
     * abutting a closing back-tick (`` `t`WHERE ``) is still delimited — needed by the
     * clause matchers (filterClauses / hasPositionalSort), not by the ones that only
     * read the first identifier (guardProjection / singleTableFrom / distinctProjection).
     */
    private function normalize(string $sql, bool $neutralizeBackticks = false): string
    {
        $cleaned = $this->stripStringLiterals(trim($this->stripComments($sql)));

        if ($neutralizeBackticks) {
            $cleaned = str_replace('`', ' ', $cleaned);
        }

        return strtolower((string) preg_replace('/\s+/', ' ', $cleaned));
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
