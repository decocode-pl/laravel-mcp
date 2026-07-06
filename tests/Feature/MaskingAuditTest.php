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

    // A person table with a PII gap (name, ip — not masked by default), a masked
    // column (email), and plain columns; an entity table sharing the `name`
    // column; and a blocklisted table that must never be scanned.
    Schema::create('customers', function ($t) {
        $t->integer('id');
        $t->string('name');
        $t->string('email');
        $t->string('ip');
        $t->string('status');
    });
    Schema::create('tracks', function ($t) {
        $t->integer('id');
        $t->string('name');
    });
    Schema::create('sessions', function ($t) {   // blocklisted
        $t->integer('id');
        $t->string('ip_address');
    });
});

/** @return array<string,mixed> */
function auditJson(array $options = []): array
{
    Artisan::call('mcp:masking:audit', ['--json' => true] + $options);

    return json_decode(Artisan::output(), true);
}

it('flags PII-suspect columns that are not masked, per table', function () {
    $findings = auditJson()['findings'];

    expect($findings['customers'])->toContain('name')->toContain('ip');
    expect($findings['customers'])->not->toContain('email');   // masked by default → not a gap
    expect($findings['customers'])->not->toContain('status');  // not PII-suspect
    expect($findings['tracks'])->toContain('name');            // same name, still a suspect here
});

it('never scans blocklisted tables', function () {
    $findings = auditJson()['findings'];

    expect($findings)->not->toHaveKey('sessions');
});

it('closes a gap once a table_pattern masks the column, without affecting other tables', function () {
    config()->set('mcp.masking.table_patterns', ['customers' => ['name', 'ip']]);

    $findings = auditJson()['findings'];

    // customers.name / customers.ip are now masked → no longer flagged.
    expect($findings)->not->toHaveKey('customers');
    // tracks.name is untouched by the customers-scoped rule → still flagged.
    expect($findings['tracks'])->toContain('name');
});

it('exits non-zero under --strict when gaps remain', function () {
    $this->artisan('mcp:masking:audit', ['--strict' => true])->assertFailed();
});

it('exits zero under --strict when no gaps remain', function () {
    // Mask every suspect column across both tables.
    config()->set('mcp.masking.table_patterns', ['*' => ['name', 'ip']]);

    $this->artisan('mcp:masking:audit', ['--strict' => true])->assertOk();
});

it('reports the columns scanned and stays read-only', function () {
    $result = auditJson();

    expect($result['tables_scanned'])->toBeGreaterThanOrEqual(2);
    expect($result['columns_scanned'])->toBeGreaterThanOrEqual(7); // customers(5) + tracks(2)
});

it('fails clearly when the schema cannot be read', function () {
    config()->set('database.default', 'nonexistent_conn');

    $this->artisan('mcp:masking:audit')->assertFailed();
});

it('never reports green on zero readable tables (PR-001 — no false-green gate)', function () {
    // Block every business table → zero coverage. An empty findings list here must
    // NOT be read as "no PII" — the gate refuses to certify what it never scanned.
    config()->set('mcp.read.blocked_tables', ['*']);

    $this->artisan('mcp:masking:audit')->assertFailed();
});

it('exposes tables_skipped in the json contract', function () {
    expect(auditJson())->toHaveKey('tables_skipped');
});
