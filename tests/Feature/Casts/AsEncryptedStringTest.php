<?php

use Illuminate\Database\Eloquent\Model;
use LumenSistemas\Encrypt\Casts\AsEncryptedString;
use LumenSistemas\Encrypt\Encrypter;
use LumenSistemas\Encrypt\Facades\Encryption;
use LumenSistemas\Encrypt\ValueObjects\SecretString;

beforeEach(function (): void {
    configureKeyFiles();
    $this->app->forgetInstance(Encrypter::class);

    $this->cast = new AsEncryptedString;
    $this->model = new class extends Model {};
});

afterEach(function (): void {
    AsEncryptedString::authorizeUsing(null);
    cleanupKeyFiles();
});

describe('AsEncryptedString cast', function (): void {
    describe('set()', function (): void {
        it('encrypts a string value', function (): void {
            $result = $this->cast->set($this->model, 'secret', 'hello', []);

            expect($result)->toBeString()->not->toBe('hello');
            expect(Encryption::decrypt($result)->get())->toBe('hello');
        });

        it('returns null for null value', function (): void {
            $result = $this->cast->set($this->model, 'secret', null, []);

            expect($result)->toBeNull();
        });

        it('throws InvalidArgumentException for non-string value', function (): void {
            $this->cast->set($this->model, 'secret', 123, []);
        })->throws(InvalidArgumentException::class, 'The value must be a string.');

        it('handles empty string', function (): void {
            $result = $this->cast->set($this->model, 'secret', '', []);

            expect($result)->toBeString()->not->toBeEmpty();
        });
    });

    describe('get()', function (): void {
        it('decrypts a string value', function (): void {
            $encrypted = Encryption::encrypt(new SecretString('hello'));
            $result = $this->cast->get($this->model, 'secret', $encrypted, []);

            expect($result)->toBe('hello');
        });

        it('returns null for null value', function (): void {
            $result = $this->cast->get($this->model, 'secret', null, []);

            expect($result)->toBeNull();
        });

        it('throws InvalidArgumentException for non-string value', function (): void {
            $this->cast->get($this->model, 'secret', 123, []);
        })->throws(InvalidArgumentException::class, 'The value must be a string.');

        it('handles empty string round-trip', function (): void {
            $encrypted = $this->cast->set($this->model, 'secret', '', []);
            $result = $this->cast->get($this->model, 'secret', $encrypted, []);

            expect($result)->toBe('');
        });
    });

    describe('round-trip', function (): void {
        it('encrypts and decrypts back to the original value', function (): void {
            $encrypted = $this->cast->set($this->model, 'secret', 'my secret', []);
            $decrypted = $this->cast->get($this->model, 'secret', $encrypted, []);

            expect($decrypted)->toBe('my secret');
        });

        it('handles special characters', function (): void {
            $value = "p@ssw0rd!#$%&'\"<>\n\t";
            $encrypted = $this->cast->set($this->model, 'secret', $value, []);
            $decrypted = $this->cast->get($this->model, 'secret', $encrypted, []);

            expect($decrypted)->toBe($value);
        });

        it('produces different ciphertexts for the same input', function (): void {
            $a = $this->cast->set($this->model, 'secret', 'hello', []);
            $b = $this->cast->set($this->model, 'secret', 'hello', []);

            expect($a)->not->toBe($b);
        });
    });

    describe('authorizeUsing()', function (): void {
        it('decrypts normally when no callback is registered', function (): void {
            $encrypted = Encryption::encrypt(new SecretString('hello'));

            expect($this->cast->get($this->model, 'secret', $encrypted, []))->toBe('hello');
        });

        it('decrypts when the callback returns true', function (): void {
            AsEncryptedString::authorizeUsing(fn (): true => true);

            $encrypted = Encryption::encrypt(new SecretString('hello'));

            expect($this->cast->get($this->model, 'secret', $encrypted, []))->toBe('hello');
        });

        it('returns the masked value when the callback returns a string', function (): void {
            AsEncryptedString::authorizeUsing(fn (): string => '***.***.***-**');

            $encrypted = Encryption::encrypt(new SecretString('123.456.789-00'));

            expect($this->cast->get($this->model, 'secret', $encrypted, []))->toBe('***.***.***-**');
        });

        it('does not decrypt when the callback returns a masked value', function (): void {
            $decryptCalled = false;
            AsEncryptedString::authorizeUsing(function () use (&$decryptCalled): string {
                $decryptCalled = true;

                return '***';
            });

            // Use garbage ciphertext — decryption should never be attempted
            $this->cast->get($this->model, 'secret', 'not-a-valid-ciphertext', []);

            expect($decryptCalled)->toBeTrue();
        });

        it('propagates exceptions thrown by the callback', function (): void {
            AsEncryptedString::authorizeUsing(function (): never {
                throw new RuntimeException('Access denied');
            });

            $encrypted = Encryption::encrypt(new SecretString('hello'));

            $this->cast->get($this->model, 'secret', $encrypted, []);
        })->throws(RuntimeException::class, 'Access denied');

        it('receives the model, key, and attributes', function (): void {
            $receivedArgs = [];

            AsEncryptedString::authorizeUsing(function (Model $model, string $key, array $attributes) use (&$receivedArgs): true {
                $receivedArgs = ['model' => $model, 'key' => $key, 'attributes' => $attributes];

                return true;
            });

            $encrypted = Encryption::encrypt(new SecretString('hello'));
            $attrs = ['secret' => $encrypted, 'name' => 'test'];

            $this->cast->get($this->model, 'secret', $encrypted, $attrs);

            expect($receivedArgs['model'])->toBe($this->model);
            expect($receivedArgs['key'])->toBe('secret');
            expect($receivedArgs['attributes'])->toBe($attrs);
        });

        it('is not called for null values', function (): void {
            $called = false;
            AsEncryptedString::authorizeUsing(function () use (&$called): true {
                $called = true;

                return true;
            });

            $this->cast->get($this->model, 'secret', null, []);

            expect($called)->toBeFalse();
        });

        it('can be cleared by passing null', function (): void {
            AsEncryptedString::authorizeUsing(fn (): string => '***');
            AsEncryptedString::authorizeUsing(null);

            $encrypted = Encryption::encrypt(new SecretString('hello'));

            expect($this->cast->get($this->model, 'secret', $encrypted, []))->toBe('hello');
        });
    });
});
