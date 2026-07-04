<?php

declare(strict_types=1);

use Decocode\LaravelMcp\Security\TableBlocklist;

it('blocks control-plane and framework tables from the default config', function () {
    $blocklist = TableBlocklist::fromConfig();

    expect($blocklist->isBlocked('mcp_accounts'))->toBeTrue();
    expect($blocklist->isBlocked('oauth_access_tokens'))->toBeTrue();
    expect($blocklist->isBlocked('sessions'))->toBeTrue();
    expect($blocklist->isBlocked('personal_access_tokens'))->toBeTrue();
});

it('allows ordinary business tables', function () {
    $blocklist = TableBlocklist::fromConfig();

    expect($blocklist->isBlocked('customers'))->toBeFalse();
    expect($blocklist->isBlocked('orders'))->toBeFalse();
});

it('matches wildcards but not unrelated names', function () {
    $blocklist = new TableBlocklist(['telescope_*', 'sessions']);

    expect($blocklist->isBlocked('telescope_entries'))->toBeTrue();
    expect($blocklist->isBlocked('sessions'))->toBeTrue();
    expect($blocklist->isBlocked('session_reports'))->toBeFalse();
});
