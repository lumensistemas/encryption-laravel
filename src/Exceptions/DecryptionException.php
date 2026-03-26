<?php

declare(strict_types=1);

namespace LumenSistemas\Encrypt\Exceptions;

use Exception;

class DecryptionException extends Exception
{
    public function __construct(?string $message = null)
    {
        parent::__construct($message ?? 'Failed to decrypt the input string.');
    }
}
