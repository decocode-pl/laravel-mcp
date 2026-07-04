<?php

declare(strict_types=1);

use Decocode\LaravelMcp\Capabilities\Capability;
use Decocode\LaravelMcp\Capabilities\CapabilityResolver;
use Decocode\LaravelMcp\Models\McpServiceAccount;

beforeEach(function () {
    $this->resolver = app(CapabilityResolver::class);
});

it('denies unknown capabilities', function () {
    expect(Capability::isKnown('read'))->toBeTrue();
    expect(Capability::isKnown('teleport'))->toBeFalse();
    expect($this->resolver->allows(new McpServiceAccount, 'teleport'))->toBeFalse();
});

it('denies when there is no account', function () {
    expect($this->resolver->allows(null, 'read'))->toBeFalse();
});

it('denies delete while the kill-switch is off, regardless of grant', function () {
    config()->set('mcp.capabilities.delete_enabled', false);

    // delete-lock is checked before any per-account grant lookup
    expect($this->resolver->allows(new McpServiceAccount, 'delete'))->toBeFalse();
});

it('denies write while the kill-switch is off, regardless of grant', function () {
    config()->set('mcp.capabilities.write_enabled', false);

    // write-lock is checked before any per-account grant lookup
    expect($this->resolver->allows(new McpServiceAccount, 'write'))->toBeFalse();
});
