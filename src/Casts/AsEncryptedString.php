<?php

declare(strict_types=1);

namespace LumenSistemas\Encrypt\Casts;

use Closure;
use Illuminate\Contracts\Database\Eloquent\CastsAttributes;
use Illuminate\Database\Eloquent\Model;
use InvalidArgumentException;
use LumenSistemas\Encrypt\Facades\Encryption;
use LumenSistemas\Encrypt\ValueObjects\SecretString;

/**
 * Eloquent cast that encrypts/decrypts string attributes.
 *
 * Usage:
 *   protected $casts = ['secret' => AsEncryptedString::class];
 *
 * With an authorization/audit hook:
 *   AsEncryptedString::authorizeUsing(function (Model $model, string $key) {
 *       AuditLog::record($model, $key);
 *
 *       if (! auth()->user()->can('view-sensitive', $model)) {
 *           return '***.***.***-**'; // return masked value
 *       }
 *
 *       return true; // allow decryption
 *   });
 */
/** @implements CastsAttributes<string|null, mixed> */
class AsEncryptedString implements CastsAttributes
{
    /**
     * The callback invoked before decryption.
     *
     * It receives (Model $model, string $key, array $attributes) and should
     * return true to allow decryption, or a string to return as a masked
     * replacement. It may also throw an exception to deny access entirely.
     *
     * @var null|Closure(Model, string, array<string, mixed>): (true|string)
     */
    private static ?Closure $authorizeUsing = null;

    /**
     * Register a callback that authorizes and/or audits access before decryption.
     *
     * @param  null|Closure(Model, string, array<string, mixed>): (true|string)  $callback
     */
    public static function authorizeUsing(?Closure $callback): void
    {
        self::$authorizeUsing = $callback;
    }

    /**
     * Cast the given value.
     *
     * @param  array<string, mixed>  $attributes
     */
    public function get(Model $model, string $key, mixed $value, array $attributes): ?string
    {
        if ($value === null) {
            return null;
        }

        if (! is_string($value)) {
            throw new InvalidArgumentException('The value must be a string.');
        }

        if (self::$authorizeUsing instanceof Closure) {
            $result = (self::$authorizeUsing)($model, $key, $attributes);

            if (is_string($result)) {
                return $result;
            }
        }

        return Encryption::decrypt($value)->get();
    }

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

        return Encryption::encrypt(new SecretString($value));
    }
}
