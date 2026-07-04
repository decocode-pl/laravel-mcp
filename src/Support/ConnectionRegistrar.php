<?php

declare(strict_types=1);

namespace Decocode\LaravelMcp\Support;

use Illuminate\Contracts\Foundation\Application;

/**
 * Registers the package's dedicated MySQL connections into the app's
 * database config. Values come from config('mcp.db') (config-cache safe —
 * env() is resolved at config load time, not here).
 *
 * - mcp_ctl : control-plane (mcp_, oauth_ and audit tables) — read + write there only
 * - mcp_ro  : data-plane read — SELECT only (hard read-only guarantee)
 * - mcp_rw  : data-plane write — provisioned only when write user is configured
 */
class ConnectionRegistrar
{
    public static function register(Application $app): void
    {
        $config = $app['config'];
        $db = (array) $config->get('mcp.db', []);

        $base = [
            'driver' => 'mysql',
            'host' => $db['host'] ?? '127.0.0.1',
            'port' => $db['port'] ?? '3306',
            'database' => $db['database'] ?? null,
            'charset' => $db['charset'] ?? 'utf8mb4',
            'collation' => $db['collation'] ?? 'utf8mb4_unicode_ci',
            'prefix' => '',
            'strict' => true,
        ];

        $config->set('database.connections.mcp_ctl', array_merge($base, [
            'username' => $db['control']['username'] ?? null,
            'password' => $db['control']['password'] ?? null,
        ]));

        $config->set('database.connections.mcp_ro', array_merge($base, [
            'username' => $db['read']['username'] ?? null,
            'password' => $db['read']['password'] ?? null,
        ]));

        // Write connection only exists once a write user is provisioned.
        if (! empty($db['write']['username'])) {
            $config->set('database.connections.mcp_rw', array_merge($base, [
                'username' => $db['write']['username'],
                'password' => $db['write']['password'] ?? null,
            ]));
        }
    }
}
