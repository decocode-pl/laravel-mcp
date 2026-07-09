<?php

declare(strict_types=1);

use Decocode\LaravelMcp\Security\ColumnMasker;

it('masks sensitive columns from the default config and leaves plain ones', function () {
    $masker = ColumnMasker::fromConfig();

    expect($masker->shouldMask('password'))->toBeTrue();
    expect($masker->shouldMask('password_hash'))->toBeTrue();
    expect($masker->shouldMask('remember_token'))->toBeTrue();
    expect($masker->shouldMask('customer_bank_account'))->toBeTrue();
    expect($masker->shouldMask('pesel'))->toBeTrue();
    expect($masker->shouldMask('passport_number'))->toBeTrue();
    expect($masker->shouldMask('ssn'))->toBeTrue();
    expect($masker->shouldMask('customer_ssn'))->toBeTrue();      // *ssn*
    expect($masker->shouldMask('tax_id'))->toBeTrue();

    // Direct PII is masked by default (deny-by-default).
    expect($masker->shouldMask('email'))->toBeTrue();
    expect($masker->shouldMask('customer_email'))->toBeTrue();
    expect($masker->shouldMask('phone'))->toBeTrue();
    expect($masker->shouldMask('mobile_phone'))->toBeTrue();
    expect($masker->shouldMask('guest_first_name'))->toBeTrue();
    expect($masker->shouldMask('firstname'))->toBeTrue();         // no-underscore variant
    expect($masker->shouldMask('lastname'))->toBeTrue();
    expect($masker->shouldMask('fullname'))->toBeTrue();
    expect($masker->shouldMask('maiden_name'))->toBeTrue();
    expect($masker->shouldMask('last_name'))->toBeTrue();
    expect($masker->shouldMask('surname'))->toBeTrue();
    expect($masker->shouldMask('street'))->toBeTrue();
    expect($masker->shouldMask('address'))->toBeTrue();
    expect($masker->shouldMask('address1'))->toBeTrue();
    expect($masker->shouldMask('addresses'))->toBeTrue();
    expect($masker->shouldMask('billing_address'))->toBeTrue();
    expect($masker->shouldMask('ip_address'))->toBeTrue();       // *_address
    expect($masker->shouldMask('postcode'))->toBeTrue();
    expect($masker->shouldMask('post_code'))->toBeTrue();
    expect($masker->shouldMask('billing_zip'))->toBeTrue();       // *zip*
    expect($masker->shouldMask('zip_code'))->toBeTrue();
    expect($masker->shouldMask('date_of_birth'))->toBeTrue();
    expect($masker->shouldMask('member_dob'))->toBeTrue();        // *dob*

    // `*address*` is broad on purpose (no address column can leak) — it also
    // masks FK/morph columns, which a project un-masks via allowlist if needed.
    expect($masker->shouldMask('address_id'))->toBeTrue();
    expect($masker->shouldMask('addressable_type'))->toBeTrue();

    // Bare `name` / lookup `city` stay visible — they collide with entity/lookup
    // columns and the masker has no table context to tell a person from an event.
    expect($masker->shouldMask('name'))->toBeFalse();
    expect($masker->shouldMask('city'))->toBeFalse();
    // Verification timestamps carry no PII — un-masked via the default allowlist.
    expect($masker->shouldMask('email_verified_at'))->toBeFalse();
    expect($masker->shouldMask('phone_verified_at'))->toBeFalse();
    expect($masker->shouldMask('mobile_verified_at'))->toBeFalse();
    expect($masker->shouldMask('id'))->toBeFalse();
    expect($masker->shouldMask('status'))->toBeFalse();
    expect($masker->shouldMask('created_at'))->toBeFalse();
});

it('replaces masked values with the placeholder and keeps nulls', function () {
    $masker = ColumnMasker::fromConfig();

    expect($masker->maskValue('password', 'secret'))->toBe('[masked]');
    expect($masker->maskValue('password', null))->toBeNull();
    expect($masker->maskValue('email', 'a@b.pl'))->toBe('[masked]');
    expect($masker->maskValue('name', 'Jan'))->toBe('Jan');
});

it('honours the un-mask allowlist', function () {
    $masker = new ColumnMasker(['*token*'], ['api_token'], [], '[masked]');

    expect($masker->shouldMask('reset_token'))->toBeTrue();
    expect($masker->shouldMask('api_token'))->toBeFalse();
});

it('lets a project expose a masked FK for joins via the allowlist', function () {
    // The broad `*address*` masks `address_id`; allowlisting it restores joins
    // while the address text itself stays masked.
    $masker = new ColumnMasker(['*address*'], ['address_id'], [], '[masked]');

    expect($masker->shouldMask('address_id'))->toBeFalse();
    expect($masker->shouldMask('billing_address'))->toBeTrue();
});

it('applies partial maskers for email and last4', function () {
    $masker = new ColumnMasker(['email', 'card_number'], [], [
        'email' => 'email',
        'card_number' => 'last4',
    ], '[masked]');

    expect($masker->maskValue('email', 'jan.kowalski@decocode.pl'))->toBe('j***@decocode.pl');
    expect($masker->maskValue('card_number', '4111 1111 1111 1234'))->toBe('****1234');
});

it('masks a whole row by column name', function () {
    $masker = new ColumnMasker(['password'], [], [], '[masked]');

    expect($masker->maskRow(['id' => 5, 'name' => 'Jan', 'password' => 'x']))
        ->toBe(['id' => 5, 'name' => 'Jan', 'password' => '[masked]']);
});

it('scrubs PII nested in a JSON column whose own name is not sensitive (PR-001)', function () {
    // 'print_job_payloads' matches no pattern, but its JSON hides a pesel.
    $masker = new ColumnMasker(['*pesel*'], [], [], '[masked]', true);

    $row = $masker->maskRow([
        'id' => 1,
        'print_job_payloads' => json_encode(['buyer' => ['pesel' => '44051401359', 'name' => 'Jan']]),
    ]);

    $decoded = json_decode($row['print_job_payloads'], true);
    expect($decoded['buyer']['pesel'])->toBe('[masked]');
    expect($decoded['buyer']['name'])->toBe('Jan');
});

it('does not touch JSON columns when scrubbing is disabled', function () {
    $masker = new ColumnMasker(['*pesel*'], [], [], '[masked]', false);
    $json = json_encode(['pesel' => '44051401359']);

    expect($masker->maskRow(['payload' => $json])['payload'])->toBe($json);
});

// ---- Table-qualified masking (0.3.0) -------------------------------------

it('masks a per-table column only within its table, leaving the same name elsewhere', function () {
    // `name` is not a global pattern; table_patterns marks it PII in `customers`.
    $masker = new ColumnMasker(
        patterns: [], allowlist: [], partial: [], placeholder: '[masked]',
        scrubJson: false,
        tablePatterns: ['customers' => ['name']],
    );

    expect($masker->shouldMask('name', 'customers'))->toBeTrue();   // person
    expect($masker->shouldMask('name', 'tracks'))->toBeFalse();     // entity label
    expect($masker->shouldMask('name'))->toBeFalse();               // no table context → name-based only
    expect($masker->maskRow(['name' => 'Jan'], 'customers'))->toBe(['name' => '[masked]']);
    expect($masker->maskRow(['name' => 'Techno'], 'tracks'))->toBe(['name' => 'Techno']);
});

it('supports glob patterns on both the table and column side', function () {
    $masker = new ColumnMasker(
        patterns: [], allowlist: [], partial: [], placeholder: '[masked]',
        scrubJson: false,
        tablePatterns: ['*' => ['ip', 'ip_forwarded'], 'revisions' => ['old', 'new']],
    );

    expect($masker->shouldMask('ip', 'anything'))->toBeTrue();       // '*' table key
    expect($masker->shouldMask('old', 'revisions'))->toBeTrue();
    expect($masker->shouldMask('old', 'products'))->toBeFalse();
});

it('lets a table-scoped allowlist expose a globally-masked column in one table only', function () {
    // Broad `*address*` masks address_id everywhere; expose it in `orders` alone.
    $masker = new ColumnMasker(
        patterns: ['*address*'], allowlist: [], partial: [], placeholder: '[masked]',
        scrubJson: false,
        tableAllowlist: ['orders' => ['address_id']],
    );

    expect($masker->shouldMask('address_id', 'orders'))->toBeFalse();     // exposed here
    expect($masker->shouldMask('address_id', 'customers'))->toBeTrue();   // still masked elsewhere
    expect($masker->shouldMask('address_id'))->toBeTrue();                // and with no table context
    expect($masker->shouldMask('billing_address', 'orders'))->toBeTrue(); // allowlist is column-specific
});

it('gives table_allowlist precedence over table_patterns', function () {
    $masker = new ColumnMasker(
        patterns: [], allowlist: [], partial: [], placeholder: '[masked]',
        scrubJson: false,
        tablePatterns: ['customers' => ['*']],
        tableAllowlist: ['customers' => ['id']],
    );

    expect($masker->shouldMask('id', 'customers'))->toBeFalse();     // allowlist wins
    expect($masker->shouldMask('name', 'customers'))->toBeTrue();    // pattern still applies
});

it('reads table-qualified maps from config', function () {
    config()->set('mcp.masking', [
        'patterns' => [],
        'allowlist' => [],
        'partial' => [],
        'placeholder' => '[masked]',
        'scrub_json' => false,
        'table_patterns' => ['customers' => ['name']],
        'table_allowlist' => ['orders' => ['address_id']],
    ]);

    $masker = ColumnMasker::fromConfig();

    expect($masker->shouldMask('name', 'customers'))->toBeTrue();
    expect($masker->shouldMask('name', 'tracks'))->toBeFalse();
});

it('finds the first masked identifier in a SQL fragment (oracle guard helper)', function () {
    $masker = new ColumnMasker(['*email*', 'password'], [], [], '[masked]');

    // A masked column referenced anywhere in the fragment is reported.
    expect($masker->firstMaskedIdentifier("email like 'a%'"))->toBe('email');
    expect($masker->firstMaskedIdentifier('status = 1 and password is not null'))->toBe('password');

    // Nothing masked → null; empty fragment → null.
    expect($masker->firstMaskedIdentifier('id = 1 and status = 2'))->toBeNull();
    expect($masker->firstMaskedIdentifier(''))->toBeNull();
});

it('scans identifiers with a leading digit (back-ticked column names)', function () {
    // A back-ticked column may start with a digit; dropping it would miss an
    // exact-match pattern. Bare numbers are scanned but never match a column.
    $masker = new ColumnMasker(['2fa_secret'], [], [], '[masked]');

    expect($masker->firstMaskedIdentifier("where  2fa_secret = ''"))->toBe('2fa_secret');
    expect($masker->firstMaskedIdentifier('where id > 500'))->toBeNull();
});

it('honours per-table masking when scanning a fragment', function () {
    // `name` is PII only in customers (a table pattern), plain elsewhere.
    $masker = new ColumnMasker(
        patterns: [],
        allowlist: [],
        partial: [],
        placeholder: '[masked]',
        scrubJson: false,
        tablePatterns: ['customers' => ['name']],
    );

    expect($masker->firstMaskedIdentifier('name = 1', 'customers'))->toBe('name');
    expect($masker->firstMaskedIdentifier('name = 1', 'tracks'))->toBeNull();
    expect($masker->firstMaskedIdentifier('name = 1'))->toBeNull();   // no table context
});
