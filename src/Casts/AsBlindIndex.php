<?php

declare(strict_types=1);

namespace LumenSistemas\Encrypt\Casts;

use Illuminate\Contracts\Database\Eloquent\CastsInboundAttributes;
use Illuminate\Database\Eloquent\Model;
use InvalidArgumentException;
use LumenSistemas\Encrypt\Facades\Encryption;
use LumenSistemas\Encrypt\ValueObjects\SecretString;

/**
 * Inbound-only Eloquent cast that stores a deterministic, authenticated hash
 * (blind index) of the attribute value.
 *
 * This is useful for searching encrypted columns: store the encrypted value in
 * one column and the blind index in another, then query against the index.
 *
 * Because this is an inbound cast, reading the attribute returns the raw
 * stored hash — no transformation is applied on retrieval.
 *
 * Usage:
 *   protected $casts = [
 *       'email_encrypted' => AsEncryptedString::class,
 *       'email_index'     => AsBlindIndex::class,
 *   ];
 */
class AsBlindIndex implements CastsInboundAttributes
{
    /**
     * Prepare the given value for storage.
     *
     * @param  array<string, mixed>  $attributes
     */
    public function set(Model $model, string $key, mixed $value, array $attributes): ?string
    {
        if ($value === null) {
            return null;
        }

        if (! is_string($value)) {
            throw new InvalidArgumentException('The value must be a string.');
        }

        return Encryption::hash(new SecretString($value));
    }
}
