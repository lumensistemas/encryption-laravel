<?php

use Illuminate\Contracts\Database\Eloquent\CastsInboundAttributes;
use Illuminate\Database\Eloquent\Model;
use LumenSistemas\Encrypt\Casts\AsBlindIndex;
use LumenSistemas\Encrypt\Encrypter;
use LumenSistemas\Encrypt\Facades\Encryption;
use LumenSistemas\Encrypt\ValueObjects\SecretString;

beforeEach(function (): void {
    configureKeyFiles();
    $this->app->forgetInstance(Encrypter::class);

    $this->cast = new AsBlindIndex;
    $this->model = new class extends Model {};
});

afterEach(function (): void {
    cleanupKeyFiles();
});

describe('AsBlindIndex cast', function (): void {
    describe('set()', function (): void {
        it('returns a hash string', function (): void {
            $result = $this->cast->set($this->model, 'email_index', 'user@example.com', []);

            expect($result)->toBeString()->not->toBeEmpty();
        });

        it('does not contain the plaintext', function (): void {
            $result = $this->cast->set($this->model, 'email_index', 'user@example.com', []);

            expect($result)->not->toContain('user@example.com');
        });

        it('is deterministic — same input produces the same hash', function (): void {
            $a = $this->cast->set($this->model, 'email_index', 'user@example.com', []);
            $b = $this->cast->set($this->model, 'email_index', 'user@example.com', []);

            expect($a)->toBe($b);
        });

        it('produces different hashes for different inputs', function (): void {
            $a = $this->cast->set($this->model, 'email_index', 'a@example.com', []);
            $b = $this->cast->set($this->model, 'email_index', 'b@example.com', []);

            expect($a)->not->toBe($b);
        });

        it('returns null for null value', function (): void {
            $result = $this->cast->set($this->model, 'email_index', null, []);

            expect($result)->toBeNull();
        });

        it('throws InvalidArgumentException for non-string value', function (): void {
            $this->cast->set($this->model, 'email_index', 123, []);
        })->throws(InvalidArgumentException::class, 'The value must be a string.');

        it('produces a hash verifiable via Encryption::verify()', function (): void {
            $hash = $this->cast->set($this->model, 'email_index', 'user@example.com', []);

            expect(Encryption::verify(new SecretString('user@example.com'), $hash))->toBeTrue();
            expect(Encryption::verify(new SecretString('other@example.com'), $hash))->toBeFalse();
        });
    });

    it('implements CastsInboundAttributes', function (): void {
        expect($this->cast)
            ->toBeInstanceOf(CastsInboundAttributes::class);
    });
});
