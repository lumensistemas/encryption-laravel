<?php

use LumenSistemas\Encrypt\ValueObjects\SecretString;

describe('SecretString', function (): void {
    it('returns the actual value via get()', function (): void {
        $secret = new SecretString('secret');

        expect($secret->get())->toBe('secret');
    });

    it('returns a placeholder when cast to string', function (): void {
        $secret = new SecretString('secret');

        expect((string) $secret)->toBe('*');
    });

    it('does not expose the value in __debugInfo()', function (): void {
        $secret = new SecretString('secret');

        expect($secret->__debugInfo())->toBe([]);
    });

    it('does not expose the value in var_dump output', function (): void {
        $secret = new SecretString('secret');

        ob_start();
        var_dump($secret);
        $output = ob_get_clean();

        expect($output)->not->toContain('secret');
    });

    it('does not include the value when serialized via __sleep()', function (): void {
        $secret = new SecretString('secret');

        expect($secret->__sleep())->toBe([]);
    });

    it('does not expose the value when serialized', function (): void {
        $secret = new SecretString('secret');

        $serialized = serialize($secret);

        expect($serialized)->not->toContain('secret');
    });

    it('implements Stringable', function (): void {
        $secret = new SecretString('secret');

        expect($secret)->toBeInstanceOf(Stringable::class);
    });

    it('handles empty string', function (): void {
        $secret = new SecretString('');

        expect($secret->get())->toBe('');
        expect((string) $secret)->toBe('*');
    });

    it('handles special characters', function (): void {
        $value = "p@ssw0rd!#$%&'\"";
        $secret = new SecretString($value);

        expect($secret->get())->toBe($value);
        expect((string) $secret)->toBe('*');
    });

    it('throws RuntimeException when unserialized via __unserialize()', function (): void {
        $secret = new SecretString('secret');
        $secret->__unserialize([]);
    })->throws(RuntimeException::class, 'SecretString cannot be deserialized.');

    it('throws RuntimeException when unserialized via __wakeup()', function (): void {
        $secret = new SecretString('secret');
        $secret->__wakeup();
    })->throws(RuntimeException::class, 'SecretString cannot be deserialized.');
});
