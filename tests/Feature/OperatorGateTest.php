<?php

declare(strict_types=1);

use Decocode\LaravelMcp\Contracts\McpOperatorCheck;
use Decocode\LaravelMcp\Http\Middleware\EnsureMcpOperator;
use Decocode\LaravelMcp\Models\McpServiceAccount;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Route;

const OPERATOR_GATE_REDIRECT = 'https://claude.ai/api/mcp/auth_callback';

/** Operator check that always says yes and defers the account to config. */
class OperatorGateAllow implements McpOperatorCheck
{
    public function authorize(Request $request): bool
    {
        return true;
    }

    public function serviceAccountId(): ?int
    {
        return null;
    }
}

/** Operator check that always refuses. */
class OperatorGateDeny implements McpOperatorCheck
{
    public function authorize(Request $request): bool
    {
        return false;
    }

    public function serviceAccountId(): ?int
    {
        return null;
    }
}

/** Operator check that pins a specific service account as resource owner. */
class OperatorGatePinned implements McpOperatorCheck
{
    public function authorize(Request $request): bool
    {
        return true;
    }

    public function serviceAccountId(): ?int
    {
        return (int) config('tests.pinned_account_id');
    }
}

/** Minimal operator identity for the Gate (session) path — no DB row needed. */
class OperatorGateUser extends Authenticatable
{
    protected $guarded = [];
}

beforeEach(function () {
    // Service accounts live on the control-plane connection — isolate it in memory.
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

    // The session guard the service account is logged into as OAuth resource owner.
    config()->set('auth.guards.mcp_web', ['driver' => 'session', 'provider' => 'mcp_service']);
    config()->set('auth.providers.mcp_service', [
        'driver' => 'eloquent',
        'model' => McpServiceAccount::class,
    ]);

    config()->set('mcp.oauth.account', 'diag');
    config()->set('mcp.oauth.redirect_allowlist', [OPERATOR_GATE_REDIRECT]);
    config()->set('mcp.oauth.web_guard', 'mcp_web');
    config()->set('mcp.oauth.operator_check', null);
    config()->set('mcp.oauth.operator_gate', null);
    config()->set('mcp.oauth.operator_guard', 'web');

    // Stand in for Passport's authorize route; the handler reports the resolved
    // resource owner and the (forced) prompt so tests can assert both.
    Route::middleware([StartSession::class, EnsureMcpOperator::class])
        ->get('/oauth/authorize', fn () => 'sub='.Auth::guard('mcp_web')->id().';prompt='.request('prompt'))
        ->name('passport.authorizations.authorize');

    // A differently-named route to prove the middleware only acts on authorize.
    Route::middleware([StartSession::class, EnsureMcpOperator::class])
        ->get('/elsewhere', fn () => 'untouched')
        ->name('some.other.route');
});

function authorizeUrl(string $redirect = OPERATOR_GATE_REDIRECT): string
{
    return '/oauth/authorize?redirect_uri='.urlencode($redirect);
}

it('passes non-authorize routes straight through', function () {
    $this->get('/elsewhere')->assertOk()->assertSee('untouched');
});

// --- operator_check path ---------------------------------------------------

it('refuses when the operator check denies', function () {
    config()->set('mcp.oauth.operator_check', OperatorGateDeny::class);

    $this->get(authorizeUrl())->assertForbidden();
});

it('rejects a redirect_uri outside the allowlist', function () {
    config()->set('mcp.oauth.operator_check', OperatorGateAllow::class);
    McpServiceAccount::create(['name' => 'diag']);

    $this->get(authorizeUrl('https://evil.example/callback'))->assertForbidden();
});

it('500s when the service account is not provisioned', function () {
    config()->set('mcp.oauth.operator_check', OperatorGateAllow::class);

    $this->get(authorizeUrl())->assertStatus(500);
});

it('500s when the service account is revoked', function () {
    config()->set('mcp.oauth.operator_check', OperatorGateAllow::class);
    McpServiceAccount::create(['name' => 'diag', 'revoked_at' => now()]);

    $this->get(authorizeUrl())->assertStatus(500);
});

it('logs the config service account in as resource owner and forces consent', function () {
    config()->set('mcp.oauth.operator_check', OperatorGateAllow::class);
    $account = McpServiceAccount::create(['name' => 'diag']);

    $this->get(authorizeUrl())
        ->assertOk()
        ->assertSee('sub='.$account->getKey())
        ->assertSee('prompt=consent');
});

it('honours a service account id chosen by the operator check', function () {
    McpServiceAccount::create(['name' => 'diag']);            // config default
    $pinned = McpServiceAccount::create(['name' => 'other']); // explicitly chosen

    config()->set('tests.pinned_account_id', $pinned->getKey());
    config()->set('mcp.oauth.operator_check', OperatorGatePinned::class);

    $this->get(authorizeUrl())
        ->assertOk()
        ->assertSee('sub='.$pinned->getKey());
});

// --- operator_gate (session) path ------------------------------------------

it('fails closed when neither a gate nor a check is configured', function () {
    // Even an authenticated operator must be refused — "who may authorize" is undefined.
    $this->actingAs(new OperatorGateUser, 'web');

    $this->get(authorizeUrl())->assertForbidden();
});

it('bounces an unauthenticated operator to login (gate path)', function () {
    config()->set('mcp.oauth.operator_gate', 'mcp-operator');
    Gate::define('mcp-operator', fn ($u) => true);

    $this->get(authorizeUrl())->assertRedirect();
});

it('403s an authenticated operator the gate denies', function () {
    config()->set('mcp.oauth.operator_gate', 'mcp-operator');
    Gate::define('mcp-operator', fn ($u) => false);
    $this->actingAs(new OperatorGateUser, 'web');

    $this->get(authorizeUrl())->assertForbidden();
});

it('lets an authenticated operator the gate allows through', function () {
    config()->set('mcp.oauth.operator_gate', 'mcp-operator');
    Gate::define('mcp-operator', fn ($u) => true);
    $this->actingAs(new OperatorGateUser, 'web');
    $account = McpServiceAccount::create(['name' => 'diag']);

    $this->get(authorizeUrl())
        ->assertOk()
        ->assertSee('sub='.$account->getKey())
        ->assertSee('prompt=consent');
});
