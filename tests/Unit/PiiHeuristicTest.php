<?php

declare(strict_types=1);

use Decocode\LaravelMcp\Security\PiiHeuristic;

it('flags column names that look like PII', function (string $column) {
    expect(PiiHeuristic::looksLikePii($column))->toBeTrue();
})->with([
    // Names (incl. Polish / legacy spellings that slipped past name-based review)
    'name', 'customer_name', 'firstname', 'imie', 'nazwisko', 'odbiorca_mail',
    // Contact
    'email', 'customer_email', 'phone', 'telefon', 'mobile_number',
    // Address
    'address', 'billing_address', 'ulica', 'miasto', 'city', 'post_code', 'kodpocztowy',
    // Identifiers
    'pesel', 'nip', 'regon', 'ssn', 'iban', 'bank_account', 'card_number',
    // Short whole-token matches
    'ip', 'client_ip', 'old', 'old_values', 'new', 'plec',
    // Free-form carriers
    'kierowca', 'pasazer', 'recipient', 'notka', 'komentarz', 'user_agent',
    // Secrets & crypto material (full-schema secret sweep — 0.3.1)
    'hmac_key', 'auth_key', 'p256dh_key', 'encryption_key', 'secret_key',
    'laravel_session_id', 'session_token', 'password_hash', 'password_salt',
    'api_secret', 'client_secret', 'jwt', 'otp_code', 'cipher_text', 'nonce',
    'credentials',
    // camelCase
    'oldValue', 'clientIp',
]);

it('does not flag plainly non-PII column names', function (string $column) {
    expect(PiiHeuristic::looksLikePii($column))->toBeFalse();
})->with([
    'id', 'status', 'created_at', 'updated_at', 'quantity', 'amount', 'total',
    'price', 'gold', 'renew', 'page_count', 'is_active', 'sort_order', 'slug',
    'currency', 'weight',
    // `key`/`salt`/`hash` are whole-token (SHORT), so substring look-alikes stay
    // clean: `hashtag` is not `hash`, `monkey` not `key`, `asphalt` not `salt`.
    'monkey', 'turkey', 'asphalt', 'hashtag',
]);
