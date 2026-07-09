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
    'SELECT c.name FROM customers c WHERE c.id = 1',   // single-table alias: still fine
    'SELECT DISTINCT status FROM orders',
    'SELECT 1',
    'SELECT id, join_date FROM members WHERE join_date > 1', // `join_date` column is not a JOIN
    'SELECT * FROM `order` WHERE id = 1', // single table named after a reserved word: still one table
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

it('guardProjection rejects JOINs and comma-joins (evade table-qualified masking)', function (string $sql) {
    expect(fn () => $this->guard->guardProjection($sql))->toThrow(QueryGuardException::class);
})->with([
    'SELECT o.*, c.name FROM orders o JOIN customers c ON o.customer_id = c.id', // was previously allowed
    'SELECT c.name FROM customers c JOIN orders o ON o.customer_id = c.id',       // explicit JOIN
    'SELECT * FROM customers c LEFT JOIN orders o ON o.customer_id = c.id',       // LEFT JOIN
    'SELECT * FROM customers c INNER JOIN orders o ON o.id = c.id',               // INNER JOIN
    'SELECT * FROM customers CROSS JOIN orders',                                  // CROSS JOIN
    'SELECT a.id FROM a STRAIGHT_JOIN b ON a.id = b.id',                          // STRAIGHT_JOIN
    'SELECT * FROM customers, orders',                                            // comma-join
    'SELECT c.name, o.id FROM customers c, orders o WHERE c.id = o.customer_id',  // comma-join with WHERE
    // PR-001: first table named after a clause keyword (back-ticked reserved word)
    // must not let the JOIN slip past the clause-boundary split.
    'SELECT c.name FROM `order` JOIN customers c ON c.id = `order`.customer_id',
    'SELECT c.name FROM `group` STRAIGHT_JOIN customers c ON 1 = 1',
    'SELECT * FROM `limit`, customers',
]);

it('guardProjection rejects subqueries anywhere (table-context oracle)', function (string $sql) {
    expect(fn () => $this->guard->guardProjection($sql))->toThrow(QueryGuardException::class);
})->with([
    'subquery in WHERE'        => ["SELECT id FROM orders WHERE customer_id IN (SELECT id FROM customers WHERE name LIKE 'a%')"],
    'scalar subquery in WHERE' => ['SELECT id FROM customers WHERE id = (SELECT max(id) FROM customers)'],
    'subquery no space'        => ['SELECT id FROM customers WHERE id IN(SELECT id FROM orders)'],
    'derived table in FROM'    => ['SELECT * FROM (SELECT password AS x FROM customers) t'],
]);

it('guardProjection rejects window functions and the WINDOW clause (ordering oracle)', function (string $sql) {
    expect(fn () => $this->guard->guardProjection($sql))->toThrow(QueryGuardException::class);
})->with([
    'named WINDOW + OVER'   => ['SELECT id FROM users WINDOW w AS (PARTITION BY password) ORDER BY SUM(id) OVER w'],
    'inline OVER partition' => ['SELECT id FROM users ORDER BY SUM(id) OVER (PARTITION BY password)'],
    'RANK over named window' => ['SELECT id FROM users ORDER BY RANK() OVER w'],
]);

it('guardProjection does not trip on columns that merely contain over/window', function () {
    $this->guard->guardProjection('SELECT id FROM customers WHERE handover_date > 1');
    $this->guard->guardProjection('SELECT id FROM orders WHERE window_start = 1');

    expect(true)->toBeTrue();
});

it('assertNoSubquery rejects a subquery and passes a plain condition', function () {
    expect(fn () => $this->guard->assertNoSubquery('SELECT 1 WHERE id IN (SELECT id FROM users)'))
        ->toThrow(QueryGuardException::class);
    expect(fn () => $this->guard->assertNoSubquery('SELECT 1 WHERE id IN(SELECT id FROM users)'))
        ->toThrow(QueryGuardException::class);

    // A value list and a literal that merely contains "select" are fine.
    $this->guard->assertNoSubquery('SELECT 1 WHERE id IN (1, 2, 3)');
    $this->guard->assertNoSubquery("SELECT 1 WHERE note = '(select x)'");

    expect(true)->toBeTrue();
});

it('guardProjection allows an IN list and a literal that merely contains select', function () {
    // A value list is not a subquery; a string literal is stripped before the scan.
    $this->guard->guardProjection('SELECT id FROM customers WHERE id IN (1, 2, 3)');
    $this->guard->guardProjection("SELECT id FROM customers WHERE note = '(select x)'");

    expect(true)->toBeTrue();
});

it('rejects MySQL executable comments that hide SQL from the guard (SECURITY-001)', function (string $sql) {
    // Executed by MySQL, stripped by stripComments() — must be rejected at BOTH gates.
    expect(fn () => $this->guard->guardProjection($sql))->toThrow(QueryGuardException::class);
    expect(fn () => $this->guard->validate($sql))->toThrow(QueryGuardException::class);
    expect(fn () => $this->guard->sanitize($sql, 100))->toThrow(QueryGuardException::class);
})->with([
    'SELECT * FROM orders o /*!JOIN*/ customers c ON o.customer_id = c.id', // hidden JOIN → PII leak
    'SELECT * FROM orders o /*!50000 JOIN*/ customers c ON o.id = c.id',    // versioned executable comment
    'SELECT id FROM t /*!UNION SELECT password FROM users*/',               // hidden set operation
    'SELECT /*!12345 password */ FROM users',                              // hidden projection column
]);

it('still allows ordinary (non-executable) block comments', function () {
    $this->guard->validate('SELECT id /* just a note */ FROM customers');
    $this->guard->guardProjection('SELECT id /* just a note */ FROM customers');
})->throwsNoExceptions();

it('rejects an executable comment hidden by crafted quotes regardless of sql_mode (SECURITY-002)', function () {
    // `\'` reads as an escaped quote to backslash-based literal stripping (which would
    // swallow the whole span incl. the marker), but under NO_BACKSLASH_ESCAPES MySQL
    // closes the first literal and executes the comment. A raw byte scan rejects it.
    $sql = "SELECT id FROM orders WHERE note = 'x\\' /*!JOIN*/ customers c ON 1=1";
    expect(fn () => $this->guard->sanitize($sql, 100))->toThrow(QueryGuardException::class);
    expect(fn () => $this->guard->guardProjection($sql))->toThrow(QueryGuardException::class);
});

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
    'reserved-word table' => ['SELECT * FROM `order`', 'order'],
    'reserved-word + where' => ['SELECT * FROM `order` WHERE id = 1', 'order'],
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

// ---- filterClauses: WHERE/ORDER tail for the oracle guard (0.3.3) ---------

it('isolates the filter/sort tail of a SELECT', function (string $sql, string $expected) {
    expect($this->guard->filterClauses($sql))->toBe($expected);
})->with([
    'where'            => ["SELECT id FROM t WHERE email LIKE 'a%'", "where email like ''"],
    'order by'         => ['SELECT id FROM t ORDER BY pesel', 'order by pesel'],
    'group + having'   => ['SELECT city FROM t GROUP BY city HAVING count(*) > 1', 'group by city having count(*) > 1'],
    'where + order'    => ['SELECT id FROM t WHERE id = 1 ORDER BY name', 'where id = 1 order by name'],
    'no filter clause' => ['SELECT * FROM customers', ''],
    'limit only'       => ['SELECT * FROM customers LIMIT 10', ''],
]);

it('does not mistake a clause keyword inside a string literal for a real clause', function () {
    // The literal 'order by x' must be stripped, so the tail starts at the real WHERE.
    expect($this->guard->filterClauses("SELECT id FROM t WHERE note = 'order by x'"))
        ->toBe("where note = ''");
});

it('does not mistake a back-ticked table named after a clause keyword for a clause', function () {
    // `order` in back-ticks is the table, not an ORDER clause: no filter tail here.
    expect($this->guard->filterClauses('SELECT * FROM `order`'))->toBe('');
});

it('isolates the DISTINCT projection (cardinality oracle guard)', function (string $sql, ?string $expected) {
    expect($this->guard->distinctProjection($sql))->toBe($expected);
})->with([
    'distinct one column'   => ['SELECT DISTINCT password FROM users', 'password'],
    'distinct with where'   => ["SELECT DISTINCT email FROM users WHERE created_at > '2020-01-01'", 'email'],
    'distinct many columns' => ['SELECT DISTINCT id, status FROM users', 'id, status'],
    'not distinct'          => ['SELECT password FROM users', null],
    'all modifier'          => ['SELECT ALL password FROM users', null],
    'show'                  => ['SHOW TABLES', null],
]);

it('detects a positional ORDER BY / GROUP BY (deny-on-doubt oracle)', function (string $sql, bool $expected) {
    expect($this->guard->hasPositionalSort($sql))->toBe($expected);
})->with([
    'order by position'         => ['SELECT id, x FROM t ORDER BY 2', true],
    'group by position'         => ['SELECT id, x FROM t GROUP BY 2', true],
    'position among names'      => ['SELECT id, x FROM t ORDER BY name, 2', true],
    'position with DESC'        => ['SELECT id, x FROM t ORDER BY 2 DESC', true],
    'order by name'             => ['SELECT id FROM t ORDER BY name', false],
    'order by name then limit'  => ['SELECT id FROM t ORDER BY name LIMIT 10', false],
    'integer only in LIMIT'     => ['SELECT id FROM t LIMIT 2', false],
    'integer only in WHERE'     => ['SELECT id FROM t WHERE id = 2 ORDER BY name', false],
    'no sort clause'            => ['SELECT * FROM customers', false],
]);

it('captures a clause with no space around the keyword (oracle bypass regression)', function (string $sql, string $expected) {
    // MySQL needs no space AFTER the keyword (`WHERE(...)`) nor BEFORE it after a
    // closing back-tick (`` `t`WHERE ``). Either gap once produced an empty tail and
    // let a masked-column reference slip past the oracle guard — both must be caught.
    expect($this->guard->filterClauses($sql))->toBe($expected);
})->with([
    'where(' => ["SELECT id FROM customers WHERE(email LIKE 'a%')", "where(email like '')"],
    'having(' => ['SELECT id FROM customers HAVING(email > 0)', 'having(email > 0)'],
    'where( then order' => ["SELECT id FROM customers WHERE(email='x') ORDER BY id", "where(email='') order by id"],
    'back-tick table then where' => ["SELECT id FROM `customers`WHERE email = 'x'", "where email = ''"],
    'back-tick table then order by' => ['SELECT id FROM `agents`ORDER BY api_token', 'order by api_token'],
    // A FROM suffix ends in `)`, and MySQL needs no space before the clause keyword.
    'use index then where'  => ["SELECT * FROM users USE INDEX(PRIMARY)WHERE pesel = '1'", "where pesel = ''"],
    'force index then order' => ['SELECT * FROM users FORCE INDEX(idx)ORDER BY email', 'order by email'],
    'partition then where'  => ["SELECT * FROM users PARTITION(p0)WHERE pesel = '1'", "where pesel = ''"],
]);
