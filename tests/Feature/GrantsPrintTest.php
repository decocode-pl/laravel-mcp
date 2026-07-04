<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

beforeEach(function () {
    config()->set('database.connections.mcp_ctl', [
        'driver' => 'sqlite',
        'database' => ':memory:',
        'prefix' => '',
        'foreign_key_constraints' => false,
    ]);
    config()->set('database.default', 'mcp_ctl');
    config()->set('mcp.migration_connection', 'mcp_ctl');

    DB::purge('mcp_ctl');
    $this->artisan('migrate')->run();

    // Business tables + a blocklisted one + a Passport table.
    Schema::create('orders', fn ($t) => $t->integer('id'));
    Schema::create('customers', fn ($t) => $t->integer('id'));
    Schema::create('sessions', fn ($t) => $t->integer('id'));            // blocklisted
    Schema::create('oauth_access_tokens', fn ($t) => $t->integer('id')); // Passport
});

it('per-table mode grants mcp_ro only business tables and excludes secrets (§13.7)', function () {
    Artisan::call('mcp:grants:print');
    $out = Artisan::output();

    // Business tables → readable.
    expect($out)->toContain("GRANT SELECT ON `your_database`.`orders` TO 'mcp_ro'");
    expect($out)->toContain('`customers`');

    // Secret / control / oauth tables → NOT readable by mcp_ro.
    expect($out)->not->toContain("`your_database`.`sessions` TO 'mcp_ro'");
    expect($out)->not->toContain("`your_database`.`oauth_access_tokens` TO 'mcp_ro'");
    expect($out)->not->toContain("`your_database`.`mcp_accounts` TO 'mcp_ro'");

    // Control-plane still owns the real (introspected) Passport table.
    expect($out)->toContain("`your_database`.`oauth_access_tokens` TO 'mcp_ctl'");

    // No stale Passport ≤11 table, no broken REVOKE.
    expect($out)->not->toContain('oauth_personal_access_clients');
    expect($out)->not->toContain('REVOKE');
});

it('schema mode emits a single db.* read grant and no revoke', function () {
    Artisan::call('mcp:grants:print', ['--ro-mode' => 'schema']);
    $out = Artisan::output();

    expect($out)->toContain("GRANT SELECT ON `your_database`.* TO 'mcp_ro'");
    expect($out)->not->toContain("`orders` TO 'mcp_ro'");
    expect($out)->not->toContain('REVOKE');
});

it('never grants mcp_ro secret tables even when the blocklist is emptied (hard floor)', function () {
    config()->set('mcp.read.blocked_tables', []); // narrow the configurable layer to nothing
    Schema::create('personal_access_tokens', fn ($t) => $t->integer('id'));
    Schema::create('password_reset_tokens', fn ($t) => $t->integer('id'));

    Artisan::call('mcp:grants:print');
    $out = Artisan::output();

    // The security floor holds independently of the blocklist.
    expect($out)->not->toContain("`sessions` TO 'mcp_ro'");
    expect($out)->not->toContain("`personal_access_tokens` TO 'mcp_ro'");
    expect($out)->not->toContain("`password_reset_tokens` TO 'mcp_ro'");
    expect($out)->not->toContain("`mcp_accounts` TO 'mcp_ro'");

    // Real business tables are still granted.
    expect($out)->toContain("`orders` TO 'mcp_ro'");
});

it('per-table mode fails clearly when the schema cannot be read', function () {
    config()->set('database.default', 'nonexistent_conn');

    $this->artisan('mcp:grants:print')->assertFailed();
});

it('rejects an unknown ro-mode', function () {
    $this->artisan('mcp:grants:print', ['--ro-mode' => 'bogus'])->assertFailed();
});
