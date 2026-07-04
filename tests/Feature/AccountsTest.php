<?php

declare(strict_types=1);

use Decocode\LaravelMcp\Audit\AuditLogger;
use Decocode\LaravelMcp\Capabilities\Capability;
use Decocode\LaravelMcp\Capabilities\CapabilityResolver;
use Decocode\LaravelMcp\Models\McpServiceAccount;
use Illuminate\Support\Facades\DB;

beforeEach(function () {
    // Run the control-plane on an isolated in-memory SQLite database.
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

it('creates an account and grants a capability via artisan', function () {
    $this->artisan('mcp:account:create', ['name' => 'ci-bot'])->assertSuccessful();

    $account = McpServiceAccount::where('name', 'ci-bot')->firstOrFail();

    $this->artisan('mcp:account:grant', ['account' => (string) $account->getKey(), 'capability' => 'read'])
        ->assertSuccessful();

    expect($account->fresh()->hasCapability(Capability::READ))->toBeTrue();
    expect(app(CapabilityResolver::class)->allows($account->fresh(), Capability::READ))->toBeTrue();
});

it('keeps a granted delete inert until the kill-switch is enabled', function () {
    $account = McpServiceAccount::create(['name' => 'ci-bot']);
    $account->abilities()->create(['capability' => Capability::DELETE]);

    $resolver = app(CapabilityResolver::class);

    config()->set('mcp.capabilities.delete_enabled', false);
    expect($resolver->allows($account->fresh(), Capability::DELETE))->toBeFalse();

    config()->set('mcp.capabilities.delete_enabled', true);
    expect($resolver->allows($account->fresh(), Capability::DELETE))->toBeTrue();
});

it('fails closed when a scoped grant is queried without a scope', function () {
    $account = McpServiceAccount::create(['name' => 'ci-bot']);
    $account->abilities()->create(['capability' => Capability::READ, 'scope' => ['orders']]);

    $fresh = $account->fresh();

    // Scoped grant, no scope asked → denied (fail-closed).
    expect($fresh->hasCapability(Capability::READ))->toBeFalse();
    // Matching scope → allowed.
    expect($fresh->hasCapability(Capability::READ, 'orders'))->toBeTrue();
});

it('revokes a capability', function () {
    $account = McpServiceAccount::create(['name' => 'ci-bot']);
    $account->abilities()->create(['capability' => Capability::READ]);

    $this->artisan('mcp:account:revoke', ['account' => 'ci-bot', 'capability' => 'read'])->assertSuccessful();

    expect($account->fresh()->hasCapability(Capability::READ))->toBeFalse();
});

it('writes an audit row on the control-plane connection', function () {
    $account = McpServiceAccount::create(['name' => 'ci-bot']);

    app(AuditLogger::class)->log(
        channel: 'query',
        name: 'read_query',
        parameters: ['sql' => 'SELECT 1'],
        accountId: (int) $account->getKey(),
        rowCount: 1,
    );

    $row = DB::connection('mcp_ctl')->table('mcp_audit_log')->first();

    expect($row->channel)->toBe('query');
    expect($row->name)->toBe('read_query');
    expect((int) $row->row_count)->toBe(1);
});
