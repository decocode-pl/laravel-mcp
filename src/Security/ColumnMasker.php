<?php

declare(strict_types=1);

namespace Decocode\LaravelMcp\Security;

/**
 * Layer B of the read restriction: always-on, deny-by-default column masking.
 * A column whose name matches a pattern is masked regardless of which tool or
 * query surfaced it. `allowlist` un-masks specific columns; `partial` applies a
 * recognisable-but-not-readable masker (email / last4).
 *
 * TABLE-QUALIFIED masking (0.3.0): the same column name can be PII in one table
 * and a harmless label in another (`customers.name` vs `tracks.name`). When a
 * caller knows the source table it passes it in, and two extra layers apply on
 * top of the name-based ones:
 *   - `table_patterns`  — mask `column` only within matching `table`s.
 *   - `table_allowlist` — un-mask `column` only within matching `table`s (the
 *     most specific rule, so it can expose a globally-masked column — e.g. a FK
 *     — in one table without exposing it everywhere).
 * Both keys and column entries are glob patterns (PatternMatcher). Decision
 * precedence, most specific first: table_allowlist → table_patterns →
 * global allowlist → global patterns → visible. When no table context is known
 * (`$table === null`, e.g. a multi-table JOIN result or a nested JSON key) only
 * the global name-based layers run — behaviour is exactly as before 0.3.0.
 *
 * Aliasing (`SELECT password AS x`) evades name-based masking; the raw
 * `read_query` tool closes that gap by REJECTING projection aliases before a
 * query runs (see QueryGuard::guardProjection). Curated domain tools are
 * unaffected — they control their own projection.
 *
 * PR-001: nested PII inside JSON/serialized columns is handled by JsonScrubber,
 * wired into maskRow() below when `scrubJson` is on. Nested keys carry no table
 * context, so they always use the name-based decision.
 */
class ColumnMasker
{
    private ?JsonScrubber $scrubber = null;

    /**
     * @param  list<string>  $patterns
     * @param  list<string>  $allowlist
     * @param  array<string,string>  $partial
     * @param  array<string,list<string>>  $tablePatterns  table-pattern => list of column-patterns to mask
     * @param  array<string,list<string>>  $tableAllowlist  table-pattern => list of column-patterns to un-mask
     */
    public function __construct(
        private array $patterns,
        private array $allowlist,
        private array $partial,
        private string $placeholder,
        private bool $scrubJson = false,
        private array $tablePatterns = [],
        private array $tableAllowlist = [],
    ) {}

    public static function fromConfig(): self
    {
        $masking = (array) config('mcp.masking', []);

        return new self(
            (array) ($masking['patterns'] ?? []),
            array_map('strtolower', (array) ($masking['allowlist'] ?? [])),
            array_change_key_case((array) ($masking['partial'] ?? []), CASE_LOWER),
            (string) ($masking['placeholder'] ?? '[masked]'),
            (bool) ($masking['scrub_json'] ?? true),
            // Not case-folded here (unlike patterns/allowlist/partial) because
            // matchesTableRules() lower-cases both the table and column at match
            // time — the maps are nested, so a single array_change_key_case would
            // only touch the table keys anyway.
            (array) ($masking['table_patterns'] ?? []),
            (array) ($masking['table_allowlist'] ?? []),
        );
    }

    public function placeholder(): string
    {
        return $this->placeholder;
    }

    public function shouldMask(string $column, ?string $table = null): bool
    {
        $column = strtolower($column);
        $table = $table !== null ? strtolower($table) : null;

        // Table-scoped rules are the most specific: when the source table is
        // known, an explicit per-table decision wins over the global layers.
        if ($table !== null) {
            // A per-table un-mask can expose a globally-masked column in one table.
            if ($this->matchesTableRules($this->tableAllowlist, $table, $column)) {
                return false;
            }

            // A per-table pattern masks a column the global patterns miss
            // (a bare `name` in a person table, `old`/`new` in a revisions table).
            if ($this->matchesTableRules($this->tablePatterns, $table, $column)) {
                return true;
            }
        }

        if (in_array($column, $this->allowlist, true)) {
            return false;
        }

        foreach ($this->patterns as $pattern) {
            if (PatternMatcher::matches(strtolower((string) $pattern), $column)) {
                return true;
            }
        }

        return false;
    }

    /**
     * The first identifier in a raw SQL fragment that names a masked column, or
     * null if none do. Backs the filter/sort oracle guards: filtering or ordering
     * on a masked column (`WHERE api_token LIKE 'ab%'`, `ORDER BY pesel`) turns the
     * result into an existence oracle for that value, extractable bit-by-bit even
     * though the column is redacted in the projection.
     *
     * Scans bare word tokens; the caller must pass a fragment with string literals
     * already stripped (so a value like `WHERE note = 'pesel'` is not mistaken for
     * the column). `$table` carries the source table so per-table masking
     * (customers.name) is honoured — pass the same table used for maskRow().
     */
    public function firstMaskedIdentifier(string $fragment, ?string $table = null): ?string
    {
        if (trim($fragment) === '') {
            return null;
        }

        // Token = any run of identifier chars, INCLUDING a leading digit: a back-ticked
        // column may legally start with one (`` `2fa_secret` ``), and dropping the digit
        // would miss an exact-match masking pattern. Bare numbers are scanned too but
        // never match a column name, so they are harmless noise.
        preg_match_all('/[a-z0-9_]+/i', $fragment, $identifiers);

        foreach (array_unique($identifiers[0]) as $identifier) {
            if ($this->shouldMask($identifier, $table)) {
                return $identifier;
            }
        }

        return null;
    }

    public function maskValue(string $column, mixed $value, ?string $table = null): mixed
    {
        if ($value === null || ! $this->shouldMask($column, $table)) {
            return $value;
        }

        return match ($this->partial[strtolower($column)] ?? null) {
            'email' => $this->maskEmail((string) $value),
            'last4' => $this->maskLast4((string) $value),
            default => $this->placeholder,
        };
    }

    /**
     * @param  array<string,mixed>  $row
     * @return array<string,mixed>
     */
    public function maskRow(array $row, ?string $table = null): array
    {
        foreach ($row as $column => $value) {
            $name = (string) $column;

            // A column masked by name is redacted wholesale — no need to peek inside.
            if ($this->shouldMask($name, $table)) {
                $row[$column] = $this->maskValue($name, $value, $table);

                continue;
            }

            // Otherwise, if the value is a structured payload (JSON or PHP-serialized),
            // scrub nested PII keys (PR-001). Nested keys have no table context.
            $row[$column] = $this->scrubJson && is_string($value)
                ? $this->scrubber()->scrubString($value)
                : $value;
        }

        return $row;
    }

    /**
     * True when any table-pattern in $rules matches $table AND one of its
     * column-patterns matches $column. Both sides are glob patterns; a table key
     * of `*` therefore applies its columns to every table.
     *
     * @param  array<string,list<string>>  $rules
     */
    private function matchesTableRules(array $rules, string $table, string $column): bool
    {
        foreach ($rules as $tablePattern => $columnPatterns) {
            if (! PatternMatcher::matches(strtolower((string) $tablePattern), $table)) {
                continue;
            }

            foreach ((array) $columnPatterns as $columnPattern) {
                if (PatternMatcher::matches(strtolower((string) $columnPattern), $column)) {
                    return true;
                }
            }
        }

        return false;
    }

    private function scrubber(): JsonScrubber
    {
        return $this->scrubber ??= new JsonScrubber($this);
    }

    private function maskEmail(string $email): string
    {
        if (! str_contains($email, '@')) {
            return $this->placeholder;
        }

        [$local, $domain] = explode('@', $email, 2);
        $first = $local === '' ? '' : $local[0];

        return $first.'***@'.$domain;
    }

    private function maskLast4(string $value): string
    {
        $digits = preg_replace('/\D/', '', $value) ?? '';

        return strlen($digits) >= 4 ? '****'.substr($digits, -4) : $this->placeholder;
    }
}
