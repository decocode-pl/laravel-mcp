<?php

declare(strict_types=1);

namespace Decocode\LaravelMcp\Security;

/**
 * PR-001: recursive masking for JSON and PHP-serialized columns. ColumnMasker
 * only masks by the TOP-LEVEL result column name, so a column that is not itself
 * sensitive by name (e.g. `print_job_payloads`) leaks any PII nested inside its
 * value. This scrubber walks a decoded structure and masks every nested key
 * whose name matches the masking patterns, using the same ColumnMasker decision
 * (patterns + allowlist + partial maskers).
 *
 * SCOPE (DoD §13.5): JSON objects/arrays and PHP-serialized ARRAYS. Serialized
 * OBJECTS (`O:…`) are redacted wholesale (we never instantiate untrusted
 * classes). Any other string is returned untouched.
 */
class JsonScrubber
{
    /** Recursion cap — beyond this a nested payload is redacted (stack-DoS guard). */
    private const MAX_DEPTH = 256;

    public function __construct(private ColumnMasker $masker) {}

    /**
     * Scrub a string value that may carry a structured payload (JSON or
     * PHP-serialized). Non-structured strings are returned untouched.
     */
    public function scrubString(string $value): string
    {
        $trimmed = ltrim($value);

        if ($trimmed === '') {
            return $value;
        }

        // JSON object / array.
        if ($trimmed[0] === '{' || $trimmed[0] === '[') {
            return $this->scrubJson($value);
        }

        // PHP-serialized array (`a:N:{…}`) or object (`O:N:"Class":…`).
        if (preg_match('/^(a|O):\d+:/', $trimmed) === 1) {
            return $this->scrubSerialized($value);
        }

        return $value;
    }

    private function scrubJson(string $value): string
    {
        $decoded = json_decode($value, true);

        if (! is_array($decoded)) {
            return $value;
        }

        $encoded = json_encode(
            $this->scrub($decoded),
            JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE
        );

        // Never emit a value we could not safely re-encode (PR-010).
        return $encoded === false ? $this->masker->placeholder() : $encoded;
    }

    private function scrubSerialized(string $value): string
    {
        // allowed_classes=false → no untrusted class is ever instantiated (no
        // RCE); serialized objects decode to __PHP_Incomplete_Class, which we
        // cannot cleanly scrub, so we redact them (here and inside scrub()).
        $decoded = @unserialize($value, ['allowed_classes' => false]);

        if ($decoded === false) {
            // The a:/O: prefix matched but this is not valid serialized data
            // (a coincidental string) → leave it as-is rather than lose it.
            return $value;
        }

        if (! is_array($decoded)) {
            // Serialized object / scalar → redact wholesale rather than leak it.
            return $this->masker->placeholder();
        }

        return serialize($this->scrub($decoded));
    }

    /**
     * Recursively mask a decoded structure by key name. A key that matches a
     * masking pattern has its ENTIRE subtree masked; a value that is an OBJECT
     * (e.g. an __PHP_Incomplete_Class nested in a serialized array) is redacted
     * wholesale — we never re-emit an object subtree, which could carry PII we
     * cannot inspect by key; other keys are descended into up to MAX_DEPTH.
     *
     * @param  array<array-key,mixed>  $data
     * @return array<array-key,mixed>
     */
    public function scrub(array $data, int $depth = 0): array
    {
        foreach ($data as $key => $value) {
            if (is_object($value)) {
                $data[$key] = $this->masker->placeholder();

                continue;
            }

            if (is_string($key) && $this->masker->shouldMask($key)) {
                // Sensitive key: mask the leaf, or redact a nested subtree wholesale.
                $data[$key] = is_array($value)
                    ? $this->masker->placeholder()
                    : $this->masker->maskValue($key, $value);

                continue;
            }

            if (is_array($value)) {
                $data[$key] = $depth >= self::MAX_DEPTH
                    ? $this->masker->placeholder()
                    : $this->scrub($value, $depth + 1);
            }
        }

        return $data;
    }
}
