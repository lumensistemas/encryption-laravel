<?php

use LumenSistemas\Encrypt\Encrypter;
use LumenSistemas\Encrypt\Tests\TestCase;

pest()
    ->extends(TestCase::class)
    ->in('Feature');

/** @var list<string> */
$_keyFilesToCleanup = [];

/**
 * Write temporary key files and configure them in the app config.
 *
 * @return array{0: string, 1: string}
 */
function configureKeyFiles(): array
{
    global $_keyFilesToCleanup;

    $encPath = sys_get_temp_dir().'/encrypt_test_enc_'.bin2hex(random_bytes(4)).'.key';
    $authPath = sys_get_temp_dir().'/encrypt_test_auth_'.bin2hex(random_bytes(4)).'.key';

    file_put_contents($encPath, Encrypter::generateEncryptionKey()->get());
    file_put_contents($authPath, Encrypter::generateAuthenticationKey()->get());

    config([
        'encryption-laravel.enc_key_path' => $encPath,
        'encryption-laravel.auth_key_path' => $authPath,
    ]);

    $_keyFilesToCleanup = [$encPath, $authPath];

    return [$encPath, $authPath];
}

/**
 * Clean up temporary key files created by the current test.
 */
function cleanupKeyFiles(): void
{
    global $_keyFilesToCleanup;

    foreach ($_keyFilesToCleanup ?? [] as $_keyFileToCleanup) {
        @unlink($_keyFileToCleanup);
    }

    $_keyFilesToCleanup = [];
}
