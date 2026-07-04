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
