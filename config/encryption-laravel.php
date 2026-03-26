<?php

return [
    /*
    |--------------------------------------------------------------------------
    | Encryption Key Path
    |--------------------------------------------------------------------------
    |
    | Path to the file containing the secret key used for symmetric encryption
    | and decryption. The file must contain exactly SODIUM_CRYPTO_SECRETBOX_KEYBYTES
    | (32) bytes of raw binary data.
    |
    | Generate one with:
    |   php artisan tinker
    |   file_put_contents(storage_path('encryption.key'), Encrypter::generateEncryptionKey()->get())
    |
    */
    'enc_key_path' => env('ENCRYPT_ENC_KEY_PATH'),

    /*
    |--------------------------------------------------------------------------
    | Authentication Key Path
    |--------------------------------------------------------------------------
    |
    | Path to the file containing the secret key used to generate and verify
    | authenticated hashes (blind indexes). The file must contain exactly
    | SODIUM_CRYPTO_AUTH_KEYBYTES (32) bytes of raw binary data.
    |
    | Generate one with:
    |   php artisan tinker
    |   file_put_contents(storage_path('authentication.key'), Encrypter::generateAuthenticationKey()->get())
    |
    */
    'auth_key_path' => env('ENCRYPT_AUTH_KEY_PATH'),
];
