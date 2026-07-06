<?php

declare(strict_types=1);

use Decocode\LaravelMcp\Security\QueryGuard;
use Decocode\LaravelMcp\Security\QueryGuardException;

beforeEach(function () {
    $this->guard = new QueryGuard;
});

it('allows plain SELECT and CTE and SHOW', function (string $sql) {
    $this->guard->validate($sql);
})->with([
    'SELECT * FROM customers WHERE id = 1',
    'WITH recent AS (SELECT id FROM orders) SELECT * FROM recent',
    'SHOW TABLES',
])->throwsNoExceptions();

it('does not false-positive on soft-delete / timestamp columns', function () {
    $this->guard->validate('SELECT id, created_at, deleted_at FROM orders WHERE deleted_at IS NULL');
})->throwsNoExceptions();

it('rejects mutating statements', function (string $sql) {
    expect(fn () => $this->guard->validate($sql))->toThrow(QueryGuardException::class);
})->with([
    'UPDATE customers SET email = "x" WHERE id = 1',
    'DELETE FROM customers WHERE id = 1',
    'INSERT INTO customers (email) VALUES ("x")',
    'DROP TABLE customers',
    'TRUNCATE customers',
]);

it('rejects multiple statements', function () {
    expect(fn () => $this->guard->validate('SELECT 1; DROP TABLE customers'))
        ->toThrow(QueryGuardException::class);
});

it('rejects file exfiltration', function () {
    expect(fn () => $this->guard->validate("SELECT * FROM customers INTO OUTFILE '/tmp/x.csv'"))
        ->toThrow(QueryGuardException::class);
});

it('enforces a LIMIT when absent and leaves a smaller existing one intact', function () {
    expect($this->guard->enforceLimit('SELECT * FROM customers', 500))
        ->toBe('SELECT * FROM customers LIMIT 500');

    expect($this->guard->enforceLimit('SELECT * FROM customers LIMIT 10', 500))
        ->toBe('SELECT * FROM customers LIMIT 10');
});

it('clamps an inline LIMIT above the ceiling (PR-102)', function () {
    expect($this->guard->enforceLimit('SELECT * FROM customers LIMIT 100000', 500))
        ->toBe('SELECT * FROM customers LIMIT 500');

    // Offset preserved, only the count is clamped.
    expect($this->guard->enforceLimit('SELECT * FROM t LIMIT 10 OFFSET 20', 500))
        ->toBe('SELECT * FROM t LIMIT 10 OFFSET 20');

    expect($this->guard->enforceLimit('SELECT * FROM t LIMIT 5, 100000', 500))
        ->toBe('SELECT * FROM t LIMIT 5, 500');
});

it('appends an outer LIMIT even when a subquery already has one', function () {
    expect($this->guard->enforceLimit('SELECT * FROM (SELECT id FROM orders LIMIT 5) t', 500))
        ->toBe('SELECT * FROM (SELECT id FROM orders LIMIT 5) t LIMIT 500');
});

it('allows SELECT using functions that share a name with DML keywords', function (string $sql) {
    $this->guard->validate($sql);
})->with([
    "SELECT REPLACE(name, 'a', 'b') FROM customers",
    'SELECT TRUNCATE(price, 2) FROM products',
    "SELECT INSERT(name, 1, 0, 'x') FROM customers",
])->throwsNoExceptions();

it('rejects whitespace-padded file exfiltration', function () {
    expect(fn () => $this->guard->validate("SELECT * FROM customers INTO  OUTFILE '/tmp/x'"))
        ->toThrow(QueryGuardException::class);
});

it('does not treat a forbidden keyword inside a string literal as mutating', function () {
    $this->guard->validate("SELECT * FROM audit WHERE action = 'delete'");
})->throwsNoExceptions();

it('still rejects a real mutating statement that shares that keyword', function () {
    expect(fn () => $this->guard->validate('DELETE FROM audit WHERE action = 1'))
        ->toThrow(QueryGuardException::class);
});

it('sanitize returns a single ready-to-run SQL with an enforced LIMIT', function () {
    expect($this->guard->sanitize('SELECT * FROM t', 100))
        ->toBe('SELECT * FROM t LIMIT 100');
});

it('sanitize rejects a mutating statement', function () {
    expect(fn () => $this->guard->sanitize('UPDATE t SET a = 1', 100))
        ->toThrow(QueryGuardException::class);
});

it('guardProjection allows plain columns, wildcards and bare function calls', function (string $sql) {
    $this->guard->guardProjection($sql);
})->with([
    'SELECT * FROM customers WHERE id = 1',
    'SELECT id, name, created_at FROM customers',
    'SELECT o.*, c.name FROM orders o JOIN customers c ON o.customer_id = c.id',
    'SELECT DISTINCT status FROM orders',
    'SELECT 1',
    'SELECT id FROM orders WHERE customer_id IN (SELECT id FROM customers)', // subquery in WHERE is fine
])->throwsNoExceptions();

it('guardProjection rejects aliasing and expressions that could evade masking', function (string $sql) {
    expect(fn () => $this->guard->guardProjection($sql))->toThrow(QueryGuardException::class);
})->with([
    'SELECT password AS x FROM users',            // explicit alias
    'SELECT password pw FROM users',              // implicit alias
    'SELECT COUNT(*) total FROM orders',          // aliased function
    'SELECT price * quantity FROM order_items',   // expression
    'WITH x AS (SELECT 1) SELECT * FROM x',       // CTE not supported
    'SELECT id FROM a UNION SELECT password FROM users',       // UNION grafts PII under col 1 name
    'SELECT id FROM a INTERSECT SELECT password FROM users',   // INTERSECT
    "SELECT json_extract(meta, '$.pesel') FROM customers",     // JSON extraction bypasses scrubber
    'SELECT data->>"$.card" FROM payments',                    // -> / ->> JSON operator
    'SELECT * FROM (SELECT password AS x FROM users) t',       // derived-table alias renames PII
    'SELECT * FROM (SELECT id FROM orders) t',                 // any FROM-subquery (deny-on-doubt)
    "SELECT * FROM JSON_TABLE(data, '$' COLUMNS(x VARCHAR PATH '$.password')) j", // JSON_TABLE renames PII
    'SELECT COUNT(*) FROM orders',                             // bare function call (no functions allowed)
    'SELECT lower(email) FROM customers',                      // function wrapping evades exact-pattern masking
    "SELECT if(length('aaaaaaaa') > 0, password, null) FROM users", // padded auto-alias truncation rename
]);

// ---- singleTableFrom: table context for masking (0.3.0) ------------------

it('resolves the single source table of a plain SELECT', function (string $sql, ?string $expected) {
    expect($this->guard->singleTableFrom($sql))->toBe($expected);
})->with([
    'bare table'          => ['SELECT * FROM customers', 'customers'],
    'with WHERE'          => ['SELECT id, name FROM customers WHERE id = 1', 'customers'],
    'back-ticked'         => ['SELECT * FROM `customers`', 'customers'],
    'alias'               => ['SELECT * FROM customers c WHERE c.id = 1', 'customers'],
    'alias with AS'       => ['SELECT * FROM customers AS c', 'customers'],
    'db-qualified'        => ['SELECT * FROM shop.customers', 'customers'],
    'trailing order/limit'=> ['SELECT * FROM customers ORDER BY id LIMIT 10', 'customers'],
    'table named orders'  => ['SELECT * FROM orders WHERE status = 1', 'orders'],
]);

it('returns null when the source table is ambiguous or absent (deny-on-doubt)', function (string $sql) {
    expect($this->guard->singleTableFrom($sql))->toBeNull();
})->with([
    'explicit JOIN'   => ['SELECT * FROM customers c JOIN tracks t ON t.id = c.track_id'],
    'left join'       => ['SELECT * FROM customers LEFT JOIN orders ON orders.customer_id = customers.id'],
    'comma join'      => ['SELECT * FROM customers, orders'],
    'no from'         => ['SELECT 1'],
    'show'            => ['SHOW TABLES'],
    'explain'         => ['EXPLAIN SELECT * FROM customers'],
]);
