<?php

use Illuminate\Console\Command;

$tempDir = sys_get_temp_dir().'/encrypt_cmd_test_'.getmypid();

beforeEach(function () use ($tempDir): void {
    @mkdir($tempDir, 0755, true);
    $this->tempDir = $tempDir;
});

afterEach(function () use ($tempDir): void {
    foreach (glob($tempDir.'/*.key') ?: [] as $file) {
        @unlink($file);
    }

    @rmdir($tempDir);
});

describe('encryption:generate-keys', function (): void {
    it('generates both key files', function (): void {
        $this->artisan('encryption:generate-keys', ['--path' => $this->tempDir])
            ->assertExitCode(Command::SUCCESS);

        expect(file_exists($this->tempDir.'/encryption.key'))->toBeTrue();
        expect(file_exists($this->tempDir.'/authentication.key'))->toBeTrue();
    });

    it('generates keys of the correct length', function (): void {
        $this->artisan('encryption:generate-keys', ['--path' => $this->tempDir]);

        $encKey = file_get_contents($this->tempDir.'/encryption.key');
        $authKey = file_get_contents($this->tempDir.'/authentication.key');

        expect(mb_strlen($encKey, '8bit'))->toBe(SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
        expect(mb_strlen($authKey, '8bit'))->toBe(SODIUM_CRYPTO_AUTH_KEYBYTES);
    });

    it('sets file permissions to 0600', function (): void {
        $this->artisan('encryption:generate-keys', ['--path' => $this->tempDir]);

        expect(decoct(fileperms($this->tempDir.'/encryption.key') & 0777))->toBe('600');
        expect(decoct(fileperms($this->tempDir.'/authentication.key') & 0777))->toBe('600');
    })->skipOnWindows();

    it('refuses to overwrite existing key files', function (): void {
        file_put_contents($this->tempDir.'/encryption.key', 'existing');

        $this->artisan('encryption:generate-keys', ['--path' => $this->tempDir])
            ->assertExitCode(Command::FAILURE);

        expect(file_get_contents($this->tempDir.'/encryption.key'))->toBe('existing');
    });

    it('overwrites existing key files with --force', function (): void {
        file_put_contents($this->tempDir.'/encryption.key', 'old');
        file_put_contents($this->tempDir.'/authentication.key', 'old');

        $this->artisan('encryption:generate-keys', ['--path' => $this->tempDir, '--force' => true])
            ->assertExitCode(Command::SUCCESS);

        expect(file_get_contents($this->tempDir.'/encryption.key'))->not->toBe('old');
        expect(file_get_contents($this->tempDir.'/authentication.key'))->not->toBe('old');
    });

    it('defaults to storage_path when --path is not given', function (): void {
        $storagePath = $this->app->storagePath();

        $this->artisan('encryption:generate-keys')
            ->assertExitCode(Command::SUCCESS);

        expect(file_exists($storagePath.'/encryption.key'))->toBeTrue();
        expect(file_exists($storagePath.'/authentication.key'))->toBeTrue();

        // cleanup
        @unlink($storagePath.'/encryption.key');
        @unlink($storagePath.'/authentication.key');
    });

    it('outputs the key file paths', function (): void {
        $this->artisan('encryption:generate-keys', ['--path' => $this->tempDir])
            ->expectsOutputToContain($this->tempDir.'/encryption.key')
            ->expectsOutputToContain($this->tempDir.'/authentication.key')
            ->assertExitCode(Command::SUCCESS);
    });

    it('asks for confirmation when using --force in production', function (): void {
        $this->app->detectEnvironment(fn (): string => 'production');

        file_put_contents($this->tempDir.'/encryption.key', 'old');
        file_put_contents($this->tempDir.'/authentication.key', 'old');

        $this->artisan('encryption:generate-keys', ['--path' => $this->tempDir, '--force' => true])
            ->expectsConfirmation('You are in production. Overwriting keys will invalidate all existing encrypted data. Continue?', 'yes')
            ->assertExitCode(Command::SUCCESS);

        expect(file_get_contents($this->tempDir.'/encryption.key'))->not->toBe('old');
    });

    it('aborts when confirmation is denied in production', function (): void {
        $this->app->detectEnvironment(fn (): string => 'production');

        file_put_contents($this->tempDir.'/encryption.key', 'old');
        file_put_contents($this->tempDir.'/authentication.key', 'old');

        $this->artisan('encryption:generate-keys', ['--path' => $this->tempDir, '--force' => true])
            ->expectsConfirmation('You are in production. Overwriting keys will invalidate all existing encrypted data. Continue?', 'no')
            ->assertExitCode(Command::FAILURE);

        expect(file_get_contents($this->tempDir.'/encryption.key'))->toBe('old');
    });

    it('fails when --path directory does not exist', function (): void {
        $this->artisan('encryption:generate-keys', ['--path' => '/nonexistent/directory/path'])
            ->expectsOutputToContain('Directory does not exist')
            ->assertExitCode(Command::FAILURE);
    });

    it('fails when --path directory is not writable', function (): void {
        chmod($this->tempDir, 0444);

        $this->artisan('encryption:generate-keys', ['--path' => $this->tempDir])
            ->expectsOutputToContain('Directory is not writable')
            ->assertExitCode(Command::FAILURE);

        chmod($this->tempDir, 0755);
    })->skipOnWindows();

    it('fails when encryption key file cannot be written', function (): void {
        // Place a directory where the key file would go — file_put_contents will throw
        mkdir($this->tempDir.'/encryption.key');

        $this->artisan('encryption:generate-keys', ['--path' => $this->tempDir, '--force' => true])
            ->expectsOutputToContain('Failed to write encryption key file')
            ->assertExitCode(Command::FAILURE);

        rmdir($this->tempDir.'/encryption.key');
    });

    it('fails when authentication key file cannot be written', function (): void {
        mkdir($this->tempDir.'/authentication.key');

        $this->artisan('encryption:generate-keys', ['--path' => $this->tempDir, '--force' => true])
            ->expectsOutputToContain('Failed to write authentication key file')
            ->assertExitCode(Command::FAILURE);

        rmdir($this->tempDir.'/authentication.key');
    });

    it('does not ask for confirmation with --force outside production', function (): void {
        $this->app->detectEnvironment(fn (): string => 'staging');

        file_put_contents($this->tempDir.'/encryption.key', 'old');
        file_put_contents($this->tempDir.'/authentication.key', 'old');

        $this->artisan('encryption:generate-keys', ['--path' => $this->tempDir, '--force' => true])
            ->assertExitCode(Command::SUCCESS);

        expect(file_get_contents($this->tempDir.'/encryption.key'))->not->toBe('old');
    });
});
