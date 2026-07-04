<?php

declare(strict_types=1);

namespace Decocode\LaravelMcp\Tests;

use Decocode\LaravelMcp\McpServiceProvider;
use Orchestra\Testbench\TestCase as Orchestra;

class TestCase extends Orchestra
{
    protected function getPackageProviders($app): array
    {
        return [
            McpServiceProvider::class,
        ];
    }
}
