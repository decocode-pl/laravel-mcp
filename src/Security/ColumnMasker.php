<?php

declare(strict_types=1);

namespace Decocode\LaravelMcp\Security;

/**
 * Layer B of the read restriction: always-on, deny-by-default column masking.
 * A column whose name matches a pattern is masked regardless of which tool or
 * query surfaced it. `allowlist` un-masks specific columns; `partial` applies a
 * recognisable-but-not-readable masker (email / last4).
 *
 * Aliasing (`SELECT password AS x`) evades name-based masking; the raw
 * `read_query` tool closes that gap by REJECTING projection aliases before a
 * query runs (see QueryGuard::guardProjection). Curated domain tools are
 * unaffected — they control their own projection.
 *
 * PR-001: nested PII inside JSON/serialized columns is handled by JsonScrubber,
 * wired into maskRow() below when `scrubJson` is on.
 */
class ColumnMasker
{
    private ?JsonScrubber $scrubber = null;

    /**
     * @param  list<string>  $patterns
     * @param  list<string>  $allowlist
     * @param  array<string,string>  $partial
     */
    public function __construct(
        private array $patterns,
        private array $allowlist,
        private array $partial,
        private string $placeholder,
        private bool $scrubJson = false,
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
        );
    }

    public function placeholder(): string
    {
        return $this->placeholder;
    }

    public function shouldMask(string $column): bool
    {
        $column = strtolower($column);

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

    public function maskValue(string $column, mixed $value): mixed
    {
        if ($value === null || ! $this->shouldMask($column)) {
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
    public function maskRow(array $row): array
    {
        foreach ($row as $column => $value) {
            $name = (string) $column;

            // A column masked by name is redacted wholesale — no need to peek inside.
            if ($this->shouldMask($name)) {
                $row[$column] = $this->maskValue($name, $value);

                continue;
            }

            // Otherwise, if the value is a structured payload (JSON or PHP-serialized),
            // scrub nested PII keys (PR-001).
            $row[$column] = $this->scrubJson && is_string($value)
                ? $this->scrubber()->scrubString($value)
                : $value;
        }

        return $row;
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
