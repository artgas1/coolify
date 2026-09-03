<?php

namespace App\Exceptions;

use RuntimeException;

class TerminalCommandLimitException extends RuntimeException
{
    public function __construct(
        string $message,
        public readonly int $retryAfter,
    ) {
        parent::__construct($message);
    }
}
