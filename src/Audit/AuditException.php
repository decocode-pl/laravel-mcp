<?php

declare(strict_types=1);

namespace Decocode\LaravelMcp\Audit;

use RuntimeException;

/**
 * Thrown when an MCP call cannot be recorded to the audit trail. Callers treat
 * this as fail-closed: if we cannot log what left, we do not return the data.
 */
class AuditException extends RuntimeException {}
