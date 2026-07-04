<?php

declare(strict_types=1);

use Decocode\LaravelMcp\Support\GrantPlanner;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

it('parses granted SELECT tables and detects schema-wide grants', function () {
    $rows = [
        'GRANT USAGE ON *.* TO `mcp_ro`@`127.0.0.1`',
        'GRANT SELECT ON `app`.`orders` TO `mcp_ro`@`127.0.0.1`',
        'GRANT SELECT, SHOW VIEW ON `app`.`customers` TO `mcp_ro`@`127.0.0.1`',
        'GRANT SELECT ON `other`.`secret` TO `mcp_ro`@`127.0.0.1`', // different db → ignored
    ];

    $parsed = GrantPlanner::parseGrantedSelectTables($rows, 'app');

    expect($parsed['schemaWide'])->toBeFalse();
    expect($parsed['tables'])->toEqualCanonicalizing(['orders', 'customers']);
});

it('flags a schema-wide SELECT grant', function () {
    $rows = ['GRANT SELECT ON `app`.* TO `mcp_ro`@`127.0.0.1`'];

    expect(GrantPlanner::parseGrantedSelectTables($rows, 'app')['schemaWide'])->toBeTrue();
});

it('flags a global *.* SELECT as schema-wide', function () {
    $rows = ['GRANT SELECT ON *.* TO `mcp_ro`@`127.0.0.1`'];

    expect(GrantPlanner::parseGrantedSelectTables($rows, 'app')['schemaWide'])->toBeTrue();
});

it('does not count a column-level SELECT grant as a full table SELECT', function () {
    $rows = ['GRANT SELECT (id, name) ON `app`.`customers` TO `mcp_ro`@`127.0.0.1`'];

    $parsed = GrantPlanner::parseGrantedSelectTables($rows, 'app');

    expect($parsed['tables'])->toBe([]);
    expect($parsed['schemaWide'])->toBeFalse();
});

it('computes the missing grants case-insensitively', function () {
    $missing = GrantPlanner::missing(['orders', 'customers', 'invoices'], ['orders', 'Customers']);

    expect($missing)->toBe(['invoices']);
});

describe('businessTables introspection', function () {
    beforeEach(function () {
        config()->set('database.connections.mcp_ctl', [
            'driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '', 'foreign_key_constraints' => false,
        ]);
        config()->set('database.default', 'mcp_ctl');
        config()->set('mcp.migration_connection', 'mcp_ctl');
        DB::purge('mcp_ctl');
        test()->artisan('migrate')->run();

        Schema::create('orders', fn ($t) => $t->integer('id'));
        Schema::create('sessions', fn ($t) => $t->integer('id'));            // blocklisted
        Schema::create('oauth_access_tokens', fn ($t) => $t->integer('id')); // floor
    });

    it('excludes floor and blocklisted tables', function () {
        $business = (new GrantPlanner)->businessTables();

        expect($business)->toContain('orders');
        expect($business)->not->toContain('sessions');
        expect($business)->not->toContain('oauth_access_tokens');
        expect($business)->not->toContain('mcp_accounts');
    });

    it('keeps the floor even when the blocklist is emptied', function () {
        config()->set('mcp.read.blocked_tables', []);

        $business = (new GrantPlanner)->businessTables();

        expect($business)->not->toContain('oauth_access_tokens');
        expect($business)->not->toContain('sessions'); // 'sessions' is in the hard floor
        expect($business)->toContain('orders');
    });

    it('scopes introspection to the configured database', function () {
        // On sqlite the schema is "main"; setting it exercises the scoped path.
        config()->set('mcp.db.database', 'main');

        $business = (new GrantPlanner)->businessTables();

        expect($business)->toContain('orders');
        expect($business)->not->toContain('sessions');
    });
});
