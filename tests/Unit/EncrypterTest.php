<?php

use LumenSistemas\Encrypt\Encrypter;
use LumenSistemas\Encrypt\Exceptions\DecryptionException;
use LumenSistemas\Encrypt\ValueObjects\SecretString;

describe('constructor validation', function (): void {
    it('throws InvalidArgumentException when encryption key is too short', function (): void {
        new Encrypter(
            new SecretString(random_bytes(16)),
            Encrypter::generateAuthenticationKey(),
        );
    })->throws(InvalidArgumentException::class, 'Encryption key must be exactly 32 bytes.');

    it('throws InvalidArgumentException when encryption key is too long', function (): void {
        new Encrypter(
            new SecretString(random_bytes(64)),
            Encrypter::generateAuthenticationKey(),
        );
    })->throws(InvalidArgumentException::class, 'Encryption key must be exactly 32 bytes.');

    it('throws InvalidArgumentException when authentication key is too short', function (): void {
        new Encrypter(
            Encrypter::generateEncryptionKey(),
            new SecretString(random_bytes(16)),
        );
    })->throws(InvalidArgumentException::class, 'Authentication key must be exactly 32 bytes.');

    it('throws InvalidArgumentException when authentication key is too long', function (): void {
        new Encrypter(
            Encrypter::generateEncryptionKey(),
            new SecretString(random_bytes(64)),
        );
    })->throws(InvalidArgumentException::class, 'Authentication key must be exactly 32 bytes.');
});

describe('Encrypter', function (): void {
    beforeEach(function (): void {
        $this->manager = new Encrypter(
            Encrypter::generateEncryptionKey(),
            Encrypter::generateAuthenticationKey(),
        );
    });

    describe('generateEncryptionKey()', function (): void {
        it('returns a SecretString', function (): void {
            expect(Encrypter::generateEncryptionKey())
                ->toBeInstanceOf(SecretString::class);
        });

        it('returns a key of the correct length', function (): void {
            $key = Encrypter::generateEncryptionKey();

            expect(mb_strlen($key->get(), '8bit'))->toBe(SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
        });

        it('generates a different key on each call', function (): void {
            $a = Encrypter::generateEncryptionKey();
            $b = Encrypter::generateEncryptionKey();

            expect($a->get())->not->toBe($b->get());
        });
    });

    describe('generateAuthenticationKey()', function (): void {
        it('returns a SecretString', function (): void {
            expect(Encrypter::generateAuthenticationKey())
                ->toBeInstanceOf(SecretString::class);
        });

        it('returns a key of the correct length', function (): void {
            $key = Encrypter::generateAuthenticationKey();

            expect(mb_strlen($key->get(), '8bit'))->toBe(SODIUM_CRYPTO_AUTH_KEYBYTES);
        });

        it('generates a different key on each call', function (): void {
            $a = Encrypter::generateAuthenticationKey();
            $b = Encrypter::generateAuthenticationKey();

            expect($a->get())->not->toBe($b->get());
        });
    });

    describe('encrypt()', function (): void {
        it('returns a non-empty string', function (): void {
            $ciphertext = $this->manager->encrypt(new SecretString('secret'));

            expect($ciphertext)->toBeString()->not->toBeEmpty();
        });

        it('does not contain the plaintext', function (): void {
            $ciphertext = $this->manager->encrypt(new SecretString('secret'));

            expect($ciphertext)->not->toContain('secret');
        });

        it('produces a different ciphertext on each call (random nonce)', function (): void {
            $input = new SecretString('secret');

            $a = $this->manager->encrypt($input);
            $b = $this->manager->encrypt($input);

            expect($a)->not->toBe($b);
        });

        it('returns a valid URL-safe base64 string', function (): void {
            $ciphertext = $this->manager->encrypt(new SecretString('secret'));

            expect($ciphertext)->toMatch('/^[A-Za-z0-9_-]+$/');
        });

        it('can encrypt an empty string', function (): void {
            $ciphertext = $this->manager->encrypt(new SecretString(''));

            expect($ciphertext)->toBeString()->not->toBeEmpty();
        });
    });

    describe('decrypt()', function (): void {
        it('decrypts back to the original value', function (): void {
            $original = 'my secret value';
            $ciphertext = $this->manager->encrypt(new SecretString($original));

            $decrypted = $this->manager->decrypt($ciphertext);

            expect($decrypted)->toBeInstanceOf(SecretString::class);
            expect($decrypted->get())->toBe($original);
        });

        it('returns a SecretString', function (): void {
            $ciphertext = $this->manager->encrypt(new SecretString('secret'));

            expect($this->manager->decrypt($ciphertext))->toBeInstanceOf(SecretString::class);
        });

        it('can round-trip an empty string', function (): void {
            $ciphertext = $this->manager->encrypt(new SecretString(''));

            expect($this->manager->decrypt($ciphertext)->get())->toBe('');
        });

        it('can round-trip a string with special characters', function (): void {
            $value = "p@ssw0rd!#$%&'\"<>\n\t";
            $ciphertext = $this->manager->encrypt(new SecretString($value));

            expect($this->manager->decrypt($ciphertext)->get())->toBe($value);
        });

        it('throws DecryptionException when ciphertext is tampered with', function (): void {
            $ciphertext = $this->manager->encrypt(new SecretString('secret'));
            // Flip a byte in the middle of the base64 string (keeps it valid base64)
            $pos = (int) (strlen($ciphertext) / 2);
            $char = $ciphertext[$pos] === 'A' ? 'B' : 'A';
            $tampered = substr_replace($ciphertext, $char, $pos, 1);

            $this->manager->decrypt($tampered);
        })->throws(DecryptionException::class);

        it('throws DecryptionException when using a different encryption key', function (): void {
            $ciphertext = $this->manager->encrypt(new SecretString('secret'));

            $otherManager = new Encrypter(
                Encrypter::generateEncryptionKey(),
                Encrypter::generateAuthenticationKey(),
            );

            $otherManager->decrypt($ciphertext);
        })->throws(DecryptionException::class);

        it('DecryptionException has a default message', function (): void {
            $ciphertext = $this->manager->encrypt(new SecretString('secret'));
            $pos = (int) (strlen($ciphertext) / 2);
            $char = $ciphertext[$pos] === 'A' ? 'B' : 'A';
            $tampered = substr_replace($ciphertext, $char, $pos, 1);

            try {
                $this->manager->decrypt($tampered);
            } catch (DecryptionException $e) {
                expect($e->getMessage())->toBe('Failed to decrypt the input string.');
            }
        });

        it('throws DecryptionException for invalid base64 input', function (): void {
            $this->manager->decrypt('!!!not-valid-base64!!!');
        })->throws(DecryptionException::class);

        it('throws DecryptionException for input that is too short', function (): void {
            $shortData = sodium_bin2base64(
                random_bytes(10),
                SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING,
            );

            $this->manager->decrypt($shortData);
        })->throws(DecryptionException::class);

        it('throws DecryptionException for empty input', function (): void {
            $this->manager->decrypt('');
        })->throws(DecryptionException::class);
    });

    describe('hash()', function (): void {
        it('returns a non-empty string', function (): void {
            $hash = $this->manager->hash(new SecretString('secret'));

            expect($hash)->toBeString()->not->toBeEmpty();
        });

        it('does not contain the plaintext', function (): void {
            $hash = $this->manager->hash(new SecretString('secret'));

            expect($hash)->not->toContain('secret');
        });

        it('returns the same hash for the same input', function (): void {
            $input = new SecretString('secret');

            expect($this->manager->hash($input))->toBe($this->manager->hash($input));
        });

        it('returns different hashes for different inputs', function (): void {
            $a = $this->manager->hash(new SecretString('secret-a'));
            $b = $this->manager->hash(new SecretString('secret-b'));

            expect($a)->not->toBe($b);
        });

        it('returns a valid URL-safe base64 string', function (): void {
            $hash = $this->manager->hash(new SecretString('secret'));

            expect($hash)->toMatch('/^[A-Za-z0-9_-]+$/');
        });

        it('produces a different hash when using a different auth key', function (): void {
            $input = new SecretString('secret');

            $otherManager = new Encrypter(
                Encrypter::generateEncryptionKey(),
                Encrypter::generateAuthenticationKey(),
            );

            expect($this->manager->hash($input))->not->toBe($otherManager->hash($input));
        });
    });

    describe('verify()', function (): void {
        it('returns true for a valid hash', function (): void {
            $input = new SecretString('secret');
            $hash = $this->manager->hash($input);

            expect($this->manager->verify($input, $hash))->toBeTrue();
        });

        it('returns false for a tampered hash', function (): void {
            $input = new SecretString('secret');
            $hash = $this->manager->hash($input);
            $pos = (int) (strlen($hash) / 2);
            $char = $hash[$pos] === 'A' ? 'B' : 'A';
            $tampered = substr_replace($hash, $char, $pos, 1);

            expect($this->manager->verify($input, $tampered))->toBeFalse();
        });

        it('returns false when the input does not match the hash', function (): void {
            $hash = $this->manager->hash(new SecretString('secret'));

            expect($this->manager->verify(new SecretString('other'), $hash))->toBeFalse();
        });

        it('returns false when using a different auth key', function (): void {
            $input = new SecretString('secret');
            $hash = $this->manager->hash($input);

            $otherManager = new Encrypter(
                Encrypter::generateEncryptionKey(),
                Encrypter::generateAuthenticationKey(),
            );

            expect($otherManager->verify($input, $hash))->toBeFalse();
        });

        it('returns false for invalid base64 hash', function (): void {
            expect($this->manager->verify(new SecretString('secret'), '!!!not-valid!!!'))->toBeFalse();
        });

        it('returns false for empty hash', function (): void {
            expect($this->manager->verify(new SecretString('secret'), ''))->toBeFalse();
        });
    });
});
