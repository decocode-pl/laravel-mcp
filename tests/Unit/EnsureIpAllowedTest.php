<?php

declare(strict_types=1);

use Decocode\LaravelMcp\Http\Middleware\EnsureIpAllowed;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Symfony\Component\HttpKernel\Exception\HttpException;

function runIpMiddleware(array $config): Response
{
    config()->set('mcp.ip_allowlist', $config);

    return (new EnsureIpAllowed)->handle(
        Request::create('/'),
        fn (Request $request): Response => new Response('ok'),
    );
}

it('passes a local IP that is on the allowlist', function () {
    expect(runIpMiddleware(['enabled' => true, 'allowed' => ['127.0.0.1', '::1']])->getContent())
        ->toBe('ok');
});

it('fails closed when enabled with an empty allowlist', function () {
    expect(fn () => runIpMiddleware(['enabled' => true, 'allowed' => []]))
        ->toThrow(HttpException::class);
});

it('rejects an IP that is not on the allowlist', function () {
    expect(fn () => runIpMiddleware(['enabled' => true, 'allowed' => ['10.0.0.1']]))
        ->toThrow(HttpException::class);
});

it('is a no-op when disabled', function () {
    expect(runIpMiddleware(['enabled' => false, 'allowed' => []])->getContent())
        ->toBe('ok');
});
