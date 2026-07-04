<?php

declare(strict_types=1);

namespace Decocode\LaravelMcp\Servers;

use Decocode\LaravelMcp\Tools\CountRowsTool;
use Decocode\LaravelMcp\Tools\OrderInspectTool;
use Decocode\LaravelMcp\Tools\ReadQueryTool;
use Decocode\LaravelMcp\Tools\SchemaDescribeTool;
use Laravel\Mcp\Server;

/**
 * The MCP server exposed to Claude clients. Each tool self-filters by the
 * caller's capabilities (conditional registration via shouldRegister), so a
 * read-only identity only ever sees read tools. order.inspect additionally
 * hides itself until it is configured for a project.
 *
 * Command tools (command.run) land in F4.
 */
class DiagnosticsServer extends Server
{
    protected string $name = 'decocode-mcp-diagnostics';

    protected string $version = '0.1.0';

    protected string $instructions = 'Read-only production diagnostics for this Laravel application. '
        .'Sensitive columns are masked and writes are refused at the database level.';

    /**
     * @var array<class-string>
     */
    protected array $tools = [
        ReadQueryTool::class,
        CountRowsTool::class,
        SchemaDescribeTool::class,
        OrderInspectTool::class,
    ];
}
