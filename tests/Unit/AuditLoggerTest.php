<?php

declare(strict_types=1);

use Decocode\LaravelMcp\Audit\AuditException;
use Decocode\LaravelMcp\Audit\AuditLogger;

it('fails closed when parameters cannot be JSON-encoded (PR-010)', function () {
    // INF is unencodable even with JSON_INVALID_UTF8_SUBSTITUTE → fail closed.
    expect(fn () => app(AuditLogger::class)->log(
        channel: 'query',
        name: 'read_query',
        parameters: ['value' => INF],
    ))->toThrow(AuditException::class);
});
