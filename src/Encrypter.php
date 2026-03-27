<?php

declare(strict_types=1);

namespace LumenSistemas\Encrypt;

use InvalidArgumentException;
use LumenSistemas\Encrypt\Exceptions\DecryptionException;
use LumenSistemas\Encrypt\ValueObjects\SecretString;
use SensitiveParameter;
use SodiumException;

use function sodium_base642bin;
use function sodium_bin2base64;
use function sodium_crypto_auth;
use function sodium_crypto_auth_keygen;
use function sodium_crypto_auth_verify;
use function sodium_crypto_secretbox;
use function sodium_crypto_secretbox_keygen;
use function sodium_crypto_secretbox_open;
use function sodium_memzero;

class Encrypter
{
    /**
     * Constructor for the Encrypter class.
     *
     * The constructor takes two parameters:
     *  - the encryption key (must be exactly SODIUM_CRYPTO_SECRETBOX_KEYBYTES bytes)
     *  - the authentication key (must be exactly SODIUM_CRYPTO_AUTH_KEYBYTES bytes)
     *
     * Both keys are expected to be instances of the SecretString class,
     * which provides a secure way to handle sensitive data in memory.
     */
    public function __construct(#[SensitiveParameter] private readonly SecretString $encKey, #[SensitiveParameter] private readonly SecretString $authKey)
    {
        if (mb_strlen($encKey->get(), '8bit') !== SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
            throw new InvalidArgumentException(
                sprintf('Encryption key must be exactly %d bytes.', SODIUM_CRYPTO_SECRETBOX_KEYBYTES),
            );
        }

        if (mb_strlen($authKey->get(), '8bit') !== SODIUM_CRYPTO_AUTH_KEYBYTES) {
            throw new InvalidArgumentException(
                sprintf('Authentication key must be exactly %d bytes.', SODIUM_CRYPTO_AUTH_KEYBYTES),
            );
        }
    }

    /**
     * Generates a new encryption key.
     */
    public static function generateEncryptionKey(): SecretString
    {
        return new SecretString(sodium_crypto_secretbox_keygen());
    }

    /**
     * Generates a new authentication key.
     */
    public static function generateAuthenticationKey(): SecretString
    {
        return new SecretString(sodium_crypto_auth_keygen());
    }

    /**
     * Encrypt the input string using a secret key.
     *
     * The input string is encrypted using the secret key provided in the
     * constructor. The encrypted string is returned as a base64 encoded string,
     * which can be safely stored or transmitted.
     */
    public function encrypt(#[SensitiveParameter] SecretString $input): string
    {
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $ciphertext = sodium_crypto_secretbox($input->get(), $nonce, $this->encKey->get());

        try {
            return $this->encode($nonce.$ciphertext);
        } finally {
            sodium_memzero($nonce);
            sodium_memzero($ciphertext);
        }
    }

    /**
     * Decrypt the input string using a secret key.
     *
     * The input string is expected to be a base64 encoded string that was
     * created by the encrypt() method. The string is decrypted using the secret
     * key provided in the constructor. The decrypted string is returned as a
     * SecretString instance in order to protect the plaintext value.
     *
     * @throws DecryptionException if the input string cannot be decrypted
     */
    public function decrypt(#[SensitiveParameter] string $input): SecretString
    {
        try {
            $decoded = $this->decode($input);
        } catch (SodiumException) {
            throw new DecryptionException;
        }

        $minLength = SODIUM_CRYPTO_SECRETBOX_NONCEBYTES + SODIUM_CRYPTO_SECRETBOX_MACBYTES;

        if (mb_strlen($decoded, '8bit') < $minLength) {
            sodium_memzero($decoded);

            throw new DecryptionException;
        }

        $nonce = $this->substr($decoded, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $ciphertext = $this->substr($decoded, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        sodium_memzero($decoded);

        $plaintext = sodium_crypto_secretbox_open($ciphertext, $nonce, $this->encKey->get());
        sodium_memzero($nonce);
        sodium_memzero($ciphertext);

        if ($plaintext === false) {
            throw new DecryptionException;
        }

        return new SecretString($plaintext);
    }

    /**
     * Generate a authenticated hash of the input string.
     *
     * This hash should tipically be used to create a unique identifier for the
     * input string. This identifier can be used to verify the integrity of the
     * input string or to serve as a key in a lookup table (e.g. a database).
     *
     * The hash is not reversible, so it should not be used to store data.
     */
    public function hash(#[SensitiveParameter] SecretString $input): string
    {
        return $this->encode(sodium_crypto_auth($input->get(), $this->authKey->get()));
    }

    /**
     * Verify an authenticated hash of the input string.
     *
     * This method verifies that the input string matches the hash. If the hash
     * was created using the hash() method, this method will return true if the
     * input string matches the hash, and false otherwise.
     */
    public function verify(
        #[SensitiveParameter]
        SecretString $input,
        #[SensitiveParameter]
        string $hash,
    ): bool {
        try {
            return sodium_crypto_auth_verify(
                $this->decode($hash),
                $input->get(),
                $this->authKey->get(),
            );
        } catch (SodiumException) {
            return false;
        }
    }

    /**
     * Encode a binary string to a base64 string.
     */
    private function encode(#[SensitiveParameter] string $input): string
    {
        return sodium_bin2base64($input, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    }

    /**
     * Decode a base64 string to a binary string.
     */
    private function decode(#[SensitiveParameter] string $input): string
    {
        return sodium_base642bin($input, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    }

    /**
     * Substring function that works with binary strings.
     *
     * This function is used to extract the nonce and ciphertext from the decoded
     * string in the decrypt() method. It uses mb_substr with the '8bit' encoding
     * to ensure that it works correctly with binary data.
     */
    private function substr(#[SensitiveParameter] string $input, int $start, ?int $length = null): string
    {
        return mb_substr($input, $start, $length, '8bit');
    }
}
