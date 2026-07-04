<?php

declare(strict_types=1);

use Decocode\LaravelMcp\Models\McpServiceAccount;
use Illuminate\Support\Facades\DB;

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
});

// NOTE: minting a Passport personal access token needs Passport installed
// (keys + personal access client) — that is an app concern, verified at the
// pilot. These cover the package's own command guards, which run before Passport.

it('token:issue fails for an unknown account', function () {
    $this->artisan('mcp:token:issue', ['account' => 'ghost'])->assertFailed();
});

it('token:issue refuses a disabled account before touching Passport', function () {
    $account = McpServiceAccount::create(['name' => 'ci-bot']);
    $account->forceFill(['revoked_at' => now()])->save();

    $this->artisan('mcp:token:issue', ['account' => 'ci-bot'])
        ->expectsOutputToContain('disabled')
        ->assertFailed();
});

it('token:revoke fails for an unknown account', function () {
    $this->artisan('mcp:token:revoke', ['account' => 'ghost'])->assertFailed();
});
