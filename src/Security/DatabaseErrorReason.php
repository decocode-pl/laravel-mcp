<?php

declare(strict_types=1);

namespace Decocode\LaravelMcp\Security;

use Illuminate\Database\QueryException;
use Throwable;

/**
 * Turns a database execution error into a message that is safe to return to the
 * MCP caller. A *diagnostic* tool must tell the operator why their statement was
 * rejected — but for a PII-bearing production database the error text itself must
 * never carry row data.
 *
 * Only structural errors (SQLSTATE class 42: unknown column/table, bad syntax)
 * are surfaced verbatim: their text is derived from the statement and the schema,
 * never from a row value. Every other class collapses to a generic message —
 * notably data exceptions (class 22) and general/runtime errors (HY000) where a
 * driver can embed a column value in the message (e.g. MySQL's "Truncated
 * incorrect value: '<row value>'"). This closes the gap the masker cannot: the
 * ColumnMasker / JsonScrubber only run on the success path over result rows, so a
 * value they would have hidden must not leak through the error path instead.
 *
 * Driver note: the class-42 discriminator matches MySQL (production). SQLite (the
 * test driver) reports unknown column/table as HY000, so the same errors collapse
 * to the generic message there — the DX of a verbatim structural error is a
 * MySQL behaviour, verified against synthetic SQLSTATE codes in the unit tests
 * and to be confirmed on the pilot DB at deploy time.
 */
final class DatabaseErrorReason
{
    /** SQLSTATE classes whose message is statement/schema-derived, never row data. */
    private const SAFE_SQLSTATE_CLASSES = ['42'];

    private const GENERIC = 'The database rejected the statement.';

    public static function from(QueryException $e): string
    {
        // The driver (PDO) exception is the authoritative source of both the
        // SQLSTATE and a message free of the bound "(Connection: …, SQL: …)" tail
        // that QueryException::getMessage() appends.
        $previous = $e->getPrevious();
        $sqlstate = $previous instanceof Throwable ? (string) $previous->getCode() : (string) $e->getCode();

        if (! self::isSafeClass($sqlstate)) {
            // Data-dependent or unclassified error: never echo it — it may carry a row value.
            return self::GENERIC;
        }

        $reason = $previous instanceof Throwable ? $previous->getMessage() : $e->getMessage();

        // Belt-and-suspenders: strip any residual bound-SQL tail. This is a
        // theoretical guard — QueryException always carries a non-null previous
        // Throwable (its constructor requires one) whose PDO message has no such
        // tail, so this path is not exercised in practice.
        $reason = trim((string) preg_replace('/\s*\(Connection:.*$/s', '', $reason));

        return $reason !== '' ? $reason : self::GENERIC;
    }

    private static function isSafeClass(string $sqlstate): bool
    {
        // A SQLSTATE value is 5 chars; its first two are the class.
        return in_array(substr($sqlstate, 0, 2), self::SAFE_SQLSTATE_CLASSES, true);
    }
}
