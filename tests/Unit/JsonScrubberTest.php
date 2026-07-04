<?php

declare(strict_types=1);

use Decocode\LaravelMcp\Security\ColumnMasker;
use Decocode\LaravelMcp\Security\JsonScrubber;

function scrubber(): JsonScrubber
{
    // Patterns cover the PII keys; partial email masker to prove leaves are masked, not just redacted.
    return new JsonScrubber(new ColumnMasker(
        ['*pesel*', '*nip*', '*iban*', '*card*', '*token*', 'email'],
        [],
        ['email' => 'email'],
        '[masked]',
        true,
    ));
}

it('masks PII nested inside a JSON payload by key name', function () {
    $payload = json_encode([
        'buyer' => ['name' => 'Jan', 'pesel' => '44051401359', 'email' => 'jan@decocode.pl'],
        'invoice' => ['nip' => '1234563218', 'total' => 100],
    ]);

    $result = json_decode(scrubber()->scrubString($payload), true);

    expect($result['buyer']['pesel'])->toBe('[masked]');
    expect($result['buyer']['email'])->toBe('j***@decocode.pl');
    expect($result['invoice']['nip'])->toBe('[masked]');

    // Non-sensitive values are preserved.
    expect($result['buyer']['name'])->toBe('Jan');
    expect($result['invoice']['total'])->toBe(100);
});

it('redacts a whole nested subtree under a sensitive key', function () {
    $payload = json_encode(['card' => ['number' => '4111111111111234', 'cvv' => '123']]);

    $result = json_decode(scrubber()->scrubString($payload), true);

    expect($result['card'])->toBe('[masked]');
});

it('masks PII inside arrays of objects', function () {
    $payload = json_encode(['items' => [
        ['sku' => 'A', 'pesel' => '1'],
        ['sku' => 'B', 'pesel' => '2'],
    ]]);

    $result = json_decode(scrubber()->scrubString($payload), true);

    expect($result['items'][0]['pesel'])->toBe('[masked]');
    expect($result['items'][1]['pesel'])->toBe('[masked]');
    expect($result['items'][0]['sku'])->toBe('A');
});

it('leaves non-structured strings untouched', function () {
    expect(scrubber()->scrubString('just a plain note'))->toBe('just a plain note');
    expect(scrubber()->scrubString('12345'))->toBe('12345');
});

it('masks PII nested inside a PHP-serialized array (PR-101 / DoD §13.5)', function () {
    $payload = serialize(['buyer' => ['name' => 'Jan', 'pesel' => '44051401359']]);

    $result = unserialize(scrubber()->scrubString($payload), ['allowed_classes' => false]);

    expect($result['buyer']['pesel'])->toBe('[masked]');
    expect($result['buyer']['name'])->toBe('Jan');
});

it('redacts a PHP-serialized object wholesale (never instantiated)', function () {
    $payload = serialize((object) ['pesel' => '1']);

    expect(scrubber()->scrubString($payload))->toBe('[masked]');
});

it('redacts an object NESTED inside a serialized array (no re-serialized PII leak)', function () {
    // Non-sensitive key 'extra' holding an object that carries a PESEL.
    $payload = serialize(['note' => 'ok', 'extra' => (object) ['pesel' => '44051401359']]);

    $result = scrubber()->scrubString($payload);

    expect($result)->not->toContain('44051401359');

    $decoded = unserialize($result, ['allowed_classes' => false]);
    expect($decoded['extra'])->toBe('[masked]');
    expect($decoded['note'])->toBe('ok');
});

it('leaves a coincidental non-serialized string that looks like serialized data', function () {
    expect(scrubber()->scrubString('a:3: meeting notes'))->toBe('a:3: meeting notes');
});
