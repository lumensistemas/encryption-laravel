<?php

declare(strict_types=1);

namespace LumenSistemas\Encrypt\ValueObjects;

use RuntimeException;
use SensitiveParameter;
use Stringable;

use function sodium_memzero;

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
 * accidental exposure in certain contexts. PHP's copy-on-write semantics
 * mean that sodium_memzero() may not erase every copy of the value, but
 * it still reduces the exposure window as a defense-in-depth measure.
 */
final class SecretString implements Stringable
{
    private bool $destroyed = false;

    /**
     * SecretString constructor.
     */
    public function __construct(#[SensitiveParameter] private string $value) {}

    /**
     * Zero the sensitive value when the object is garbage collected.
     */
    public function __destruct()
    {
        $this->destroy();
    }

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
     * Prevent deserialization of the sensitive string.
     *
     * @param  array<string, mixed>  $data
     */
    public function __unserialize(array $data): void
    {
        throw new RuntimeException('SecretString cannot be deserialized.');
    }

    /**
     * Prevent deserialization of the sensitive string.
     */
    public function __wakeup(): void
    {
        throw new RuntimeException('SecretString cannot be deserialized.');
    }

    /**
     * Zero the sensitive value in memory.
     */
    public function destroy(): void
    {
        if (! $this->destroyed && $this->value !== '') {
            $copy = $this->value;
            $this->value = '';
            sodium_memzero($copy);
        }

        $this->destroyed = true;
    }

    /**
     * Returns the actual value of the sensitive string.
     */
    public function get(): string
    {
        if ($this->destroyed) {
            throw new RuntimeException('SecretString has been destroyed.');
        }

        return $this->value;
    }
}
