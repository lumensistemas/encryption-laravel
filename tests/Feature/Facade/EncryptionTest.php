<?php

use LumenSistemas\Encrypt\Encrypter;
use LumenSistemas\Encrypt\Facades\Encryption;
use LumenSistemas\Encrypt\ValueObjects\SecretString;

beforeEach(function (): void {
    configureKeyFiles();
    $this->app->forgetInstance(Encrypter::class);
});

afterEach(function (): void {
    cleanupKeyFiles();
});

describe('Encryption facade', function (): void {
    it('resolves to the Encrypter singleton', function (): void {
        expect(Encryption::getFacadeRoot())->toBeInstanceOf(Encrypter::class);
    });

    it('returns the same instance as the container', function (): void {
        expect(Encryption::getFacadeRoot())->toBe($this->app->make(Encrypter::class));
    });

    it('can encrypt and decrypt a value', function (): void {
        $ciphertext = Encryption::encrypt(new SecretString('hello'));
        $decrypted = Encryption::decrypt($ciphertext);

        expect($decrypted)->toBeInstanceOf(SecretString::class);
        expect($decrypted->get())->toBe('hello');
    });

    it('can hash and verify a value', function (): void {
        $input = new SecretString('hello');
        $hash = Encryption::hash($input);

        expect(Encryption::verify($input, $hash))->toBeTrue();
    });

    it('verify returns false for a wrong input', function (): void {
        $hash = Encryption::hash(new SecretString('hello'));

        expect(Encryption::verify(new SecretString('other'), $hash))->toBeFalse();
    });
});
