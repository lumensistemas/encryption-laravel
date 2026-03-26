<?php

declare(strict_types=1);

namespace LumenSistemas\Encrypt\Facades;

use Illuminate\Support\Facades\Facade;
use LumenSistemas\Encrypt\Encrypter;
use LumenSistemas\Encrypt\ValueObjects\SecretString;

/**
 * @method static string encrypt(SecretString $input)
 * @method static SecretString decrypt(string $input)
 * @method static string hash(SecretString $input)
 * @method static bool verify(SecretString $input, string $hash)
 * @method static SecretString generateEncryptionKey()
 * @method static SecretString generateAuthenticationKey()
 *
 * @see Encrypter
 */
class Encryption extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return Encrypter::class;
    }
}
