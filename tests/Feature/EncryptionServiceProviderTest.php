<?php

use Illuminate\Support\ServiceProvider;
use LumenSistemas\Encrypt\Encrypter;
use LumenSistemas\Encrypt\EncryptionServiceProvider;
use LumenSistemas\Encrypt\ValueObjects\SecretString;

afterEach(function (): void {
    cleanupKeyFiles();
});

describe('EncryptionServiceProvider', function (): void {
    describe('config', function (): void {
        it('merges the package config', function (): void {
            expect(config('encryption-laravel'))->toBeArray();
            expect(config('encryption-laravel.enc_key_path'))->toBeNull();
            expect(config('encryption-laravel.auth_key_path'))->toBeNull();
        });

        it('publishes the config file', function (): void {
            $provider = new EncryptionServiceProvider($this->app);
            $provider->boot();

            $publishes = ServiceProvider::pathsToPublish(
                EncryptionServiceProvider::class,
                'encryption-laravel-config',
            );

            expect($publishes)->toBeArray()->not->toBeEmpty();

            $source = array_key_first($publishes);
            expect(file_exists($source))->toBeTrue();
        });
    });

    describe('singleton binding', function (): void {
        it('resolves Encrypter from the container when key files are set', function (): void {
            configureKeyFiles();
            $this->app->forgetInstance(Encrypter::class);

            expect($this->app->make(Encrypter::class))->toBeInstanceOf(Encrypter::class);
        });

        it('returns the same instance on repeated resolutions (singleton)', function (): void {
            configureKeyFiles();
            $this->app->forgetInstance(Encrypter::class);

            $a = $this->app->make(Encrypter::class);
            $b = $this->app->make(Encrypter::class);

            expect($a)->toBe($b);
        });

        it('throws RuntimeException when enc_key_path is missing', function (): void {
            config(['encryption-laravel.enc_key_path' => null]);
            config(['encryption-laravel.auth_key_path' => '/some/path']);

            $this->app->forgetInstance(Encrypter::class);
            $this->app->make(Encrypter::class);
        })->throws(RuntimeException::class, 'ENCRYPT_ENC_KEY_PATH is not set.');

        it('throws RuntimeException when auth_key_path is missing', function (): void {
            config(['encryption-laravel.enc_key_path' => '/some/path']);
            config(['encryption-laravel.auth_key_path' => null]);

            $this->app->forgetInstance(Encrypter::class);
            $this->app->make(Encrypter::class);
        })->throws(RuntimeException::class, 'ENCRYPT_AUTH_KEY_PATH is not set.');

        it('throws RuntimeException when key file is not readable', function (): void {
            $encPath = sys_get_temp_dir().'/encrypt_test_enc_unreadable.key';
            $authPath = sys_get_temp_dir().'/encrypt_test_auth_unreadable.key';

            file_put_contents($encPath, random_bytes(SODIUM_CRYPTO_SECRETBOX_KEYBYTES));
            file_put_contents($authPath, random_bytes(SODIUM_CRYPTO_AUTH_KEYBYTES));
            chmod($encPath, 0000);
            chmod($authPath, 0000);

            config([
                'encryption-laravel.enc_key_path' => $encPath,
                'encryption-laravel.auth_key_path' => $authPath,
            ]);

            $this->app->forgetInstance(Encrypter::class);

            try {
                $this->app->make(Encrypter::class);
            } finally {
                chmod($encPath, 0600);
                chmod($authPath, 0600);
                @unlink($encPath);
                @unlink($authPath);
            }
        })->throws(RuntimeException::class, 'Key file is not readable')->skipOnWindows();

        it('throws RuntimeException when key file does not exist', function (): void {
            config([
                'encryption-laravel.enc_key_path' => '/nonexistent/encryption.key',
                'encryption-laravel.auth_key_path' => '/nonexistent/authentication.key',
            ]);

            $this->app->forgetInstance(Encrypter::class);
            $this->app->make(Encrypter::class);
        })->throws(RuntimeException::class, 'Key file does not exist');

        it('throws RuntimeException when key file is empty', function (): void {
            $encPath = sys_get_temp_dir().'/encrypt_test_enc_empty.key';
            $authPath = sys_get_temp_dir().'/encrypt_test_auth_empty.key';

            file_put_contents($encPath, '');
            file_put_contents($authPath, '');

            config([
                'encryption-laravel.enc_key_path' => $encPath,
                'encryption-laravel.auth_key_path' => $authPath,
            ]);

            $this->app->forgetInstance(Encrypter::class);
            $this->app->make(Encrypter::class);
        })->throws(RuntimeException::class, 'Key file is empty or unreadable');

        it('throws RuntimeException when key file has wrong length', function (): void {
            $encPath = sys_get_temp_dir().'/encrypt_test_enc_badlen.key';
            $authPath = sys_get_temp_dir().'/encrypt_test_auth_badlen.key';

            file_put_contents($encPath, random_bytes(16));
            file_put_contents($authPath, random_bytes(32));

            if (PHP_OS_FAMILY !== 'Windows') {
                chmod($encPath, 0600);
                chmod($authPath, 0600);
            }

            config([
                'encryption-laravel.enc_key_path' => $encPath,
                'encryption-laravel.auth_key_path' => $authPath,
            ]);

            $this->app->forgetInstance(Encrypter::class);
            $this->app->make(Encrypter::class);
        })->throws(RuntimeException::class, 'must contain exactly 32 bytes, got 16');

        it('throws RuntimeException when key file has insecure permissions', function (): void {
            $encPath = sys_get_temp_dir().'/encrypt_test_enc_perms.key';
            $authPath = sys_get_temp_dir().'/encrypt_test_auth_perms.key';

            file_put_contents($encPath, random_bytes(SODIUM_CRYPTO_SECRETBOX_KEYBYTES));
            file_put_contents($authPath, random_bytes(SODIUM_CRYPTO_AUTH_KEYBYTES));
            chmod($encPath, 0644);
            chmod($authPath, 0644);

            config([
                'encryption-laravel.enc_key_path' => $encPath,
                'encryption-laravel.auth_key_path' => $authPath,
            ]);

            $this->app->forgetInstance(Encrypter::class);
            $this->app->make(Encrypter::class);
        })->throws(RuntimeException::class, 'has insecure permissions')->skipOnWindows();
    });

    describe('resolved Encrypter', function (): void {
        beforeEach(function (): void {
            configureKeyFiles();
            $this->app->forgetInstance(Encrypter::class);
            $this->encrypter = $this->app->make(Encrypter::class);
        });

        it('can encrypt and decrypt a value', function (): void {
            $ciphertext = $this->encrypter->encrypt(new SecretString('hello'));
            $decrypted = $this->encrypter->decrypt($ciphertext);

            expect($decrypted->get())->toBe('hello');
        });

        it('can hash and verify a value', function (): void {
            $input = new SecretString('hello');
            $hash = $this->encrypter->hash($input);

            expect($this->encrypter->verify($input, $hash))->toBeTrue();
        });
    });
});
