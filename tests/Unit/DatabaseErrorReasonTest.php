<?php

declare(strict_types=1);

use Decocode\LaravelMcp\Security\DatabaseErrorReason;
use Illuminate\Database\QueryException;

/**
 * Build a QueryException whose driver (PDO) previous carries a chosen SQLSTATE.
 * PDO reports SQLSTATE as a string code, which we reproduce by assigning the
 * protected Exception::$code from inside a PDOException subclass.
 */
function syntheticQueryException(string $sqlstate, string $driverMessage, string $sql = 'select 1'): QueryException
{
    $previous = new class($driverMessage, $sqlstate) extends PDOException
    {
        public function __construct(string $message, string $sqlstate)
        {
            parent::__construct($message);
            $this->code = $sqlstate;
        }
    };

    return new QueryException('mcp_ro', $sql, [], $previous);
}

it('surfaces a structural error (SQLSTATE class 42) verbatim for operator DX', function () {
    $e = syntheticQueryException('42S22', "SQLSTATE[42S22]: Column not found: 1054 Unknown column 'payer' in 'field list'");

    $reason = DatabaseErrorReason::from($e);

    expect($reason)->toContain('Unknown column');
    expect($reason)->toContain('payer');   // schema-derived, never a row value
});

it('surfaces unknown-table (42S02) and syntax (42000) errors', function () {
    expect(DatabaseErrorReason::from(syntheticQueryException('42S02', "SQLSTATE[42S02]: Base table or view not found: 1146 Table 'db.ghost' doesn't exist")))
        ->toContain('doesn\'t exist');

    expect(DatabaseErrorReason::from(syntheticQueryException('42000', "SQLSTATE[42000]: Syntax error or access violation: 1064 You have an error in your SQL syntax")))
        ->toContain('Syntax error');
});

it('collapses a data-exception (class 22) so a row value cannot leak', function () {
    // MySQL embeds the offending COLUMN value in this class of message. That value
    // would bypass the masker (which only runs on the success path), so it must
    // never be surfaced.
    $e = syntheticQueryException('22007', "SQLSTATE[22007]: Truncated incorrect DECIMAL value: 'jan.kowalski@pii.example'");

    $reason = DatabaseErrorReason::from($e);

    expect($reason)->toBe('The database rejected the statement.');
    expect($reason)->not->toContain('jan.kowalski@pii.example');   // PII from a row is suppressed
});

it('collapses general/runtime errors (HY000) — incl. how SQLite reports unknown column', function () {
    // On the SQLite test driver an unknown column is HY000, not 42S22; it collapses
    // to the generic message. On MySQL the same logical error is class 42 and is
    // surfaced — the divergence is intentional and documented.
    $e = syntheticQueryException('HY000', 'SQLSTATE[HY000]: General error: 1 no such column: payer');

    expect(DatabaseErrorReason::from($e))->toBe('The database rejected the statement.');
});

it('never leaks the bound-SQL tail even on a surfaced structural error', function () {
    // getMessage() would carry "(Connection: …, SQL: …)"; the driver message does
    // not, and the strip is a belt-and-suspenders guard. Prove a tail is removed.
    $e = syntheticQueryException(
        '42S22',
        "SQLSTATE[42S22]: Unknown column 'x' (Connection: mcp_ro, SQL: select x from customers where email = 'leak@pii.example')"
    );

    $reason = DatabaseErrorReason::from($e);

    expect($reason)->toContain('Unknown column');
    expect($reason)->not->toContain('leak@pii.example');
    expect($reason)->not->toContain('SQL:');
});

it('falls back to generic when no SQLSTATE class matches', function () {
    expect(DatabaseErrorReason::from(syntheticQueryException('', 'weird driver message')))
        ->toBe('The database rejected the statement.');
});
