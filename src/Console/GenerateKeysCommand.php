<?php

declare(strict_types=1);

namespace LumenSistemas\Encrypt\Console;

use Illuminate\Console\Command;
use LumenSistemas\Encrypt\Encrypter;

class GenerateKeysCommand extends Command
{
    protected $signature = 'encryption:generate-keys
        {--path= : Directory where key files will be stored (defaults to storage_path())}
        {--force : Overwrite existing key files}';

    protected $description = 'Generate encryption and authentication key files';

    public function handle(): int
    {
        $path = $this->option('path');
        $directory = is_string($path) ? $path : $this->laravel->storagePath();
        $force = $this->option('force') === true;

        if (! is_dir($directory)) {
            $this->components->error(sprintf('Directory does not exist: %s', $directory));

            return self::FAILURE;
        }

        if (! is_writable($directory)) {
            $this->components->error(sprintf('Directory is not writable: %s', $directory));

            return self::FAILURE;
        }

        $encPath = $directory.'/encryption.key';
        $authPath = $directory.'/authentication.key';

        if (! $force && (file_exists($encPath) || file_exists($authPath))) {
            $this->components->error('Key files already exist. Use --force to overwrite.');

            return self::FAILURE;
        }

        if ($force && $this->laravel->environment('production')
            && ! $this->components->confirm('You are in production. Overwriting keys will invalidate all existing encrypted data. Continue?')) {
            return self::FAILURE;
        }

        try {
            file_put_contents($encPath, Encrypter::generateEncryptionKey()->get(), LOCK_EX);
        } catch (\Throwable) {
            $this->components->error(sprintf('Failed to write encryption key file: %s', $encPath));

            return self::FAILURE;
        }

        try {
            file_put_contents($authPath, Encrypter::generateAuthenticationKey()->get(), LOCK_EX);
        } catch (\Throwable) {
            $this->components->error(sprintf('Failed to write authentication key file: %s', $authPath));

            return self::FAILURE;
        }

        if (PHP_OS_FAMILY !== 'Windows') {
            chmod($encPath, 0600);
            chmod($authPath, 0600);
        }

        $this->components->info('Encryption keys generated successfully.');
        $this->components->bulletList([
            'Encryption key: '.$encPath,
            'Authentication key: '.$authPath,
        ]);

        $this->newLine();
        $this->components->warn('Add these paths to your .env file:');
        $this->line('  ENCRYPT_ENC_KEY_PATH='.$encPath);
        $this->line('  ENCRYPT_AUTH_KEY_PATH='.$authPath);

        return self::SUCCESS;
    }
}
