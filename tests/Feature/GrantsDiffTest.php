<?php

declare(strict_types=1);

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

beforeEach(function () {
    config()->set('database.connections.mcp_ctl', [
        'driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '', 'foreign_key_constraints' => false,
    ]);
    config()->set('database.default', 'mcp_ctl');
    config()->set('mcp.migration_connection', 'mcp_ctl');
    DB::purge('mcp_ctl');
    $this->artisan('migrate')->run();

    Schema::create('orders', fn ($t) => $t->integer('id'));
});

it('fails when business tables cannot be listed', function () {
    config()->set('database.default', 'nonexistent_conn');

    $this->artisan('mcp:grants:diff')->assertFailed();
});

it('fails gracefully when mcp_ro grants cannot be read (fail-safe, no blind output)', function () {
    // The mcp_ro connection is not configured here, so SHOW GRANTS cannot run —
    // the command must fail rather than emit grants on an unknown state.
    config()->set('mcp.read.connection', 'mcp_ro');

    $this->artisan('mcp:grants:diff')->assertFailed();
});
