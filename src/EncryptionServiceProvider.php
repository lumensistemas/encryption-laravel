<?php

declare(strict_types=1);

namespace LumenSistemas\Encrypt;

use Illuminate\Support\ServiceProvider;
use LumenSistemas\Encrypt\Console\GenerateKeysCommand;
use LumenSistemas\Encrypt\ValueObjects\SecretString;
use RuntimeException;

class EncryptionServiceProvider extends ServiceProvider
{
    #[\Override]
    public function register(): void
    {
        $this->mergeConfigFrom(
            __DIR__.'/../config/encryption-laravel.php',
            'encryption-laravel',
        );

        $this->app->alias(Encrypter::class, 'encryption-laravel');

        $this->app->singleton(Encrypter::class, function (): Encrypter {
            $encKeyPath = config('encryption-laravel.enc_key_path');
            $authKeyPath = config('encryption-laravel.auth_key_path');

            if (! is_string($encKeyPath) || $encKeyPath === '') {
                throw new RuntimeException('ENCRYPT_ENC_KEY_PATH is not set.');
            }

            if (! is_string($authKeyPath) || $authKeyPath === '') {
                throw new RuntimeException('ENCRYPT_AUTH_KEY_PATH is not set.');
            }

            return new Encrypter(
                $this->readKeyFile($encKeyPath, 'ENCRYPT_ENC_KEY_PATH'),
                $this->readKeyFile($authKeyPath, 'ENCRYPT_AUTH_KEY_PATH'),
            );
        });
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->commands([GenerateKeysCommand::class]);

            $this->publishes([
                __DIR__.'/../config/encryption-laravel.php' => config_path('encryption-laravel.php'),
            ], 'encryption-laravel-config');
        }
    }

    private function readKeyFile(string $path, string $configName): SecretString
    {
        if (! file_exists($path)) {
            throw new RuntimeException(sprintf('Key file does not exist: %s (%s).', $configName, $path));
        }

        if (! is_readable($path)) {
            throw new RuntimeException(sprintf('Key file is not readable: %s (%s).', $configName, $path));
        }

        $contents = file_get_contents($path);

        if ($contents === false || $contents === '') {
            throw new RuntimeException(sprintf('Key file is empty or unreadable: %s (%s).', $configName, $path));
        }

        return new SecretString($contents);
    }
}
