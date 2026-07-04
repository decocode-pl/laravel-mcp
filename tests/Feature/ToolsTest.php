<?php

declare(strict_types=1);

use Decocode\LaravelMcp\Audit\AuditLogger;
use Decocode\LaravelMcp\Capabilities\Capability;
use Decocode\LaravelMcp\Capabilities\CapabilityResolver;
use Decocode\LaravelMcp\Models\McpServiceAccount;
use Decocode\LaravelMcp\Tools\CountRowsTool;
use Decocode\LaravelMcp\Tools\OrderInspectTool;
use Decocode\LaravelMcp\Tools\ReadQueryTool;
use Decocode\LaravelMcp\Tools\SchemaDescribeTool;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Laravel\Mcp\Request;

beforeEach(function () {
    // Isolated in-memory SQLite for both control-plane and read connections.
    foreach (['mcp_ctl', 'mcp_ro'] as $conn) {
        config()->set("database.connections.{$conn}", [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
            'foreign_key_constraints' => false,
        ]);
    }
    config()->set('database.default', 'mcp_ctl');
    config()->set('mcp.migration_connection', 'mcp_ctl');
    config()->set('mcp.read.connection', 'mcp_ro');

    // A guard so the tools can resolve the acting MCP identity in tests.
    config()->set('auth.guards.mcp', ['driver' => 'session', 'provider' => 'mcp_service']);
    config()->set('auth.providers.mcp_service', ['driver' => 'eloquent', 'model' => McpServiceAccount::class]);
    config()->set('mcp.auth.guard', 'mcp');

    DB::purge('mcp_ctl');
    DB::purge('mcp_ro');
    $this->artisan('migrate')->run();

    // Business data lives on the read connection.
    Schema::connection('mcp_ro')->create('customers', function ($table): void {
        $table->integer('id');
        $table->string('name');
        $table->string('email');
        $table->string('password');
        $table->text('meta')->nullable();
    });
    DB::connection('mcp_ro')->table('customers')->insert([
        'id' => 1,
        'name' => 'Jan',
        'email' => 'jan@decocode.pl',
        'password' => 'secret',
        'meta' => json_encode(['buyer' => ['pesel' => '44051401359', 'city' => 'Kraków']]),
    ]);
});

function readAccount(): McpServiceAccount
{
    $account = McpServiceAccount::create(['name' => 'reader']);
    $account->abilities()->create(['capability' => Capability::READ]);

    return $account;
}

function callTool(object $tool, array $args)
{
    return $tool->handle(new Request($args), app(CapabilityResolver::class), app(AuditLogger::class));
}

it('read_query masks sensitive columns and scrubs nested JSON PII', function () {
    test()->actingAs(readAccount(), 'mcp');

    $response = callTool(app(ReadQueryTool::class), [
        'sql' => 'SELECT id, name, email, password, meta FROM customers',
    ]);

    expect($response->isError())->toBeFalse();

    $row = json_decode((string) $response->content(), true)['rows'][0];

    expect($row['password'])->toBe('[masked]');   // masked by column name
    expect($row['name'])->toBe('Jan');             // bare name stays visible (entity-name collision)
    expect($row['email'])->toBe('[masked]');       // direct PII masked by default

    $meta = json_decode($row['meta'], true);
    expect($meta['buyer']['pesel'])->toBe('[masked]');   // PR-001 nested scrub
    expect($meta['buyer']['city'])->toBe('Kraków');
});

it('read_query rejects column aliasing (masking evasion)', function () {
    test()->actingAs(readAccount(), 'mcp');

    $response = callTool(app(ReadQueryTool::class), ['sql' => 'SELECT password AS pw FROM customers']);

    expect($response->isError())->toBeTrue();
});

it('read_query refuses a blocked table', function () {
    test()->actingAs(readAccount(), 'mcp');
    Schema::connection('mcp_ro')->create('sessions', fn ($t) => $t->integer('id'));

    $response = callTool(app(ReadQueryTool::class), ['sql' => 'SELECT * FROM sessions']);

    expect($response->isError())->toBeTrue();
});

it('read_query refuses a blocked table smuggled via a comma-join', function () {
    test()->actingAs(readAccount(), 'mcp');
    Schema::connection('mcp_ro')->create('sessions', fn ($t) => $t->integer('id'));

    $response = callTool(app(ReadQueryTool::class), ['sql' => 'SELECT * FROM customers, sessions']);

    expect($response->isError())->toBeTrue();
});

it('read_query refuses a UNION that would graft PII past the masker', function () {
    test()->actingAs(readAccount(), 'mcp');

    $response = callTool(app(ReadQueryTool::class), [
        'sql' => 'SELECT id FROM customers UNION SELECT password FROM customers',
    ]);

    expect($response->isError())->toBeTrue();
});

it('read_query refuses a derived-table alias that would rename PII past the masker', function () {
    test()->actingAs(readAccount(), 'mcp');

    $response = callTool(app(ReadQueryTool::class), [
        'sql' => 'SELECT * FROM (SELECT password AS x FROM customers) t',
    ]);

    expect($response->isError())->toBeTrue();
});

it('read_query refuses a function-wrapped projection that could rename PII', function () {
    test()->actingAs(readAccount(), 'mcp');

    // A padded auto-alias would truncate past the "password" substring, evading name masking.
    $response = callTool(app(ReadQueryTool::class), [
        'sql' => "SELECT if(length('aaaaaaaa') > 0, password, null) FROM customers",
    ]);

    expect($response->isError())->toBeTrue();
});

it('read_query records a fail-closed audit row', function () {
    test()->actingAs(readAccount(), 'mcp');

    callTool(app(ReadQueryTool::class), ['sql' => 'SELECT id FROM customers']);

    $audit = DB::connection('mcp_ctl')->table('mcp_audit_log')->where('name', 'read_query')->first();
    expect($audit)->not->toBeNull();
    expect($audit->channel)->toBe('query');
});

it('hides tools from an identity without the read capability', function () {
    $account = McpServiceAccount::create(['name' => 'noperm']);
    test()->actingAs($account, 'mcp');

    $resolver = app(CapabilityResolver::class);

    expect(app(ReadQueryTool::class)->shouldRegister(new Request([]), $resolver))->toBeFalse();

    // ...and refuses execution even if invoked directly.
    $response = callTool(app(ReadQueryTool::class), ['sql' => 'SELECT * FROM customers']);
    expect($response->isError())->toBeTrue();
});

it('shows read tools to an identity with the read capability', function () {
    test()->actingAs(readAccount(), 'mcp');

    expect(app(ReadQueryTool::class)->shouldRegister(new Request([]), app(CapabilityResolver::class)))->toBeTrue();
});

it('count_rows returns an aggregate count and no row data', function () {
    test()->actingAs(readAccount(), 'mcp');
    DB::connection('mcp_ro')->table('customers')->insert([
        'id' => 2, 'name' => 'Ola', 'email' => 'ola@decocode.pl', 'password' => 'x', 'meta' => null,
    ]);

    $response = callTool(app(CountRowsTool::class), ['table' => 'customers']);
    $payload = json_decode((string) $response->content(), true);

    expect($response->isError())->toBeFalse();
    expect($payload['count'])->toBe(2);
    expect($payload)->not->toHaveKey('rows');
});

it('count_rows honours a WHERE filter', function () {
    test()->actingAs(readAccount(), 'mcp');

    $response = callTool(app(CountRowsTool::class), ['table' => 'customers', 'where' => "name = 'Jan'"]);

    expect(json_decode((string) $response->content(), true)['count'])->toBe(1);
});

it('count_rows refuses a blocked table', function () {
    test()->actingAs(readAccount(), 'mcp');

    $response = callTool(app(CountRowsTool::class), ['table' => 'sessions']);

    expect($response->isError())->toBeTrue();
});

it('count_rows rejects a non-identifier table (injection guard)', function () {
    test()->actingAs(readAccount(), 'mcp');

    $response = callTool(app(CountRowsTool::class), ['table' => 'customers WHERE 1=1 UNION SELECT 1']);

    expect($response->isError())->toBeTrue();
});

it('count_rows rejects a mutating WHERE fragment', function () {
    test()->actingAs(readAccount(), 'mcp');

    $response = callTool(app(CountRowsTool::class), ['table' => 'customers', 'where' => '1=1; DROP TABLE customers']);

    expect($response->isError())->toBeTrue();
});

it('count_rows rejects a set operation in the WHERE fragment', function () {
    test()->actingAs(readAccount(), 'mcp');

    $response = callTool(app(CountRowsTool::class), [
        'table' => 'customers',
        'where' => '1=1 UNION SELECT password FROM customers',
    ]);

    expect($response->isError())->toBeTrue();
});

it('count_rows refuses a WHERE that references a masked column (oracle guard)', function () {
    test()->actingAs(readAccount(), 'mcp');

    $response = callTool(app(CountRowsTool::class), [
        'table' => 'customers',
        'where' => "password LIKE 'a%'",
    ]);

    expect($response->isError())->toBeTrue();
});

it('schema.describe flags masked columns and never returns values', function () {
    test()->actingAs(readAccount(), 'mcp');

    $response = callTool(app(SchemaDescribeTool::class), ['table' => 'customers']);
    $columns = collect(json_decode((string) $response->content(), true)['columns'])->keyBy('name');

    expect($columns['password']['masked'])->toBeTrue();
    expect($columns['email']['masked'])->toBeTrue();     // direct PII masked by default
    expect($columns['name']['masked'])->toBeFalse();     // bare name stays visible
    expect($columns['password'])->not->toHaveKey('value');
});

it('schema.describe hides blocked tables from the listing', function () {
    test()->actingAs(readAccount(), 'mcp');
    Schema::connection('mcp_ro')->create('sessions', fn ($t) => $t->integer('id'));

    $response = callTool(app(SchemaDescribeTool::class), []);
    $tables = json_decode((string) $response->content(), true)['tables'];

    expect($tables)->toContain('customers');
    expect($tables)->not->toContain('sessions');
});

it('schema.describe refuses to describe a blocked table', function () {
    test()->actingAs(readAccount(), 'mcp');

    $response = callTool(app(SchemaDescribeTool::class), ['table' => 'sessions']);
    $payload = json_decode((string) $response->content(), true);

    expect($payload)->toHaveKey('error');
});

it('order.inspect is hidden until configured', function () {
    test()->actingAs(readAccount(), 'mcp');
    config()->set('mcp.tools.order_inspect', []);

    expect(app(OrderInspectTool::class)->shouldRegister(new Request([]), app(CapabilityResolver::class)))->toBeFalse();
});

it('order.inspect returns a masked record once configured', function () {
    test()->actingAs(readAccount(), 'mcp');
    config()->set('mcp.tools.order_inspect', ['table' => 'customers', 'id_column' => 'id']);

    expect(app(OrderInspectTool::class)->shouldRegister(new Request([]), app(CapabilityResolver::class)))->toBeTrue();

    $response = callTool(app(OrderInspectTool::class), ['order_id' => 1]);
    $order = json_decode((string) $response->content(), true)['order'];

    expect($order['password'])->toBe('[masked]');
    expect($order['name'])->toBe('Jan');
});
