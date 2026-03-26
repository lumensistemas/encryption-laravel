<?php

declare(strict_types=1);

namespace LumenSistemas\Encrypt\ValueObjects;

use SensitiveParameter;
use Stringable;

/**
 * Class SecretString
 *
 * This class is a wrapper around a string to protect sensitive information at
 * runtime. It is intended to be used for things like passwords, API keys, or
 * any other string that should be protected from accidental exposure in logs,
 * debug output, or other places where the value might be exposed. Altough it
 * implements Stringable, it will not return the actual value when cast to a
 * string. Instead, it will return a placeholder. The actual value can be
 * accessed only through the get() method.
 *
 * CAVEAT: This class is not secure in the general sense. It only prevents
 * accidental exposure in certain contexts. It is the responsibility of the
 * developer to ensure proper handling of the sensitive data.
 */
final readonly class SecretString implements Stringable
{
    /**
     * SecretString constructor.
     */
    public function __construct(#[SensitiveParameter] private string $value) {}

    /**
     * When cast to a string, it will return a placeholder instead of the actual
     * value.
     */
    public function __toString(): string
    {
        return '*';
    }

    /**
     * When using var_dump or similar functions, it will not show the actual
     * value.
     *
     * @return array<empty-string, never>
     */
    public function __debugInfo(): array
    {
        return [];
    }

    /**
     * When serializing the object, it will not include the actual value.
     *
     * @return array<empty-string, never>
     */
    public function __sleep(): array
    {
        return [];
    }

    /**
     * Returns the actual value of the sensitive string.
     */
    public function get(): string
    {
        return $this->value;
    }
}
