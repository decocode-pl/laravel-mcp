<?php

declare(strict_types=1);

it('loads package config with safe read-only defaults', function () {
    expect(config('mcp.masking.placeholder'))->toBe('[masked]');
    expect(config('mcp.http.enabled'))->toBeFalse();
    expect(config('mcp.ip_allowlist.enabled'))->toBeTrue();
    expect(config('mcp.commands.enabled'))->toBeFalse();
});

it('ships a non-empty table blocklist that hides control-plane tables', function () {
    $blocked = config('mcp.read.blocked_tables');

    expect($blocked)->toBeArray()->not->toBeEmpty();
    expect($blocked)->toContain('mcp_*');
    expect($blocked)->toContain('oauth_*');
});

it('registers the dedicated control-plane and read-only connections', function () {
    expect(config('database.connections.mcp_ctl'))->toBeArray();
    expect(config('database.connections.mcp_ro'))->toBeArray();

    // Write connection is absent until a write user is provisioned.
    expect(config('database.connections.mcp_rw'))->toBeNull();
});

it('registers the ip-allowlist middleware alias', function () {
    expect(app('router')->getMiddleware())->toHaveKey('mcp.ip-allowlist');
});

it('registers the channel-B operator middleware alias', function () {
    expect(app('router')->getMiddleware())->toHaveKey('mcp.operator');
});

it('ships channel-B OAuth defaults that are inert until enabled', function () {
    // Redirect allowlist is pre-pointed at the claude.ai callbacks.
    expect(config('mcp.oauth.redirect_allowlist'))
        ->toContain('https://claude.ai/api/mcp/auth_callback');

    // The package manages Passport for channel B by default, but only kicks in
    // once http.enabled is on (which it is not, by default).
    expect(config('mcp.oauth.manage_passport'))->toBeTrue();
    expect(config('mcp.http.enabled'))->toBeFalse();
});

it('ships the namespaced consent view', function () {
    expect(view()->exists('mcp::oauth-consent'))->toBeTrue();
});
