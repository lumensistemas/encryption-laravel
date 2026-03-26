# Encryption Laravel

[![Latest Version on Packagist](https://img.shields.io/packagist/v/lumensistemas/encryption-laravel.svg?style=flat-square)](https://packagist.org/packages/lumensistemas/encryption-laravel)
[![Tests](https://img.shields.io/github/actions/workflow/status/lumensistemas/encryption-laravel/run-tests.yml?branch=main&label=tests&style=flat-square)](https://github.com/lumensistemas/encryption-laravel/actions/workflows/run-tests.yml)
[![Total Downloads](https://img.shields.io/packagist/dt/lumensistemas/encryption-laravel.svg?style=flat-square)](https://packagist.org/packages/lumensistemas/encryption-laravel)

Sodium-based encryption, decryption, and blind indexing for Laravel. Provides Eloquent casts for transparent field-level encryption with optional authorization hooks (e.g. LGPD/GDPR compliance).

## Installation

```bash
composer require lumensistemas/encryption-laravel
```

Publish the configuration file:

```bash
php artisan vendor:publish --tag=encryption-laravel-config
```

Generate key files:

```bash
php artisan encryption:generate-keys
```

This creates `storage/encryption.key` and `storage/authentication.key` with `0600` permissions.

You can specify a custom directory:

```bash
php artisan encryption:generate-keys --path=/etc/secrets
```

Use `--force` to overwrite existing key files.

Add the key file paths to `.env`:

```env
ENCRYPT_ENC_KEY_PATH=/path/to/your/app/storage/encryption.key
ENCRYPT_AUTH_KEY_PATH=/path/to/your/app/storage/authentication.key
```

> **Security:** Keys are read from files rather than environment variables. This prevents accidental exposure through `phpinfo()`, debug pages, logs, or process listings. Key files should have restrictive permissions (`600`) and be excluded from version control.

## Usage

### Facade

```php
use LumenSistemas\Encrypt\Facades\Encryption;
use LumenSistemas\Encrypt\ValueObjects\SecretString;

// Encrypt & decrypt
$ciphertext = Encryption::encrypt(new SecretString('secret'));
$plaintext  = Encryption::decrypt($ciphertext)->get(); // 'secret'

// Hash & verify (blind index)
$hash = Encryption::hash(new SecretString('secret'));
Encryption::verify(new SecretString('secret'), $hash); // true
```

### Eloquent Casts

#### AsEncryptedString

Encrypts on write, decrypts on read:

```php
use LumenSistemas\Encrypt\Casts\AsEncryptedString;

class User extends Model
{
    protected $casts = [
        'cpf' => AsEncryptedString::class,
    ];
}
```

#### AsBlindIndex

Stores a deterministic hash for searching encrypted columns:

```php
use LumenSistemas\Encrypt\Casts\AsBlindIndex;
use LumenSistemas\Encrypt\Casts\AsEncryptedString;

class User extends Model
{
    protected $casts = [
        'email_encrypted' => AsEncryptedString::class,
        'email_index'     => AsBlindIndex::class,
    ];
}

// Query by blind index
use LumenSistemas\Encrypt\Facades\Encryption;
use LumenSistemas\Encrypt\ValueObjects\SecretString;

$user = User::where('email_index', Encryption::hash(new SecretString($email)))->first();
```

### Authorization & Audit Hook

Register a callback to authorize and/or log access before decryption. This is useful for LGPD/GDPR compliance:

```php
use LumenSistemas\Encrypt\Casts\AsEncryptedString;

// In a ServiceProvider boot():
AsEncryptedString::authorizeUsing(function (Model $model, string $key) {
    // Log every access
    AuditLog::record(auth()->user(), $model, $key);

    // Deny or mask
    if (! auth()->user()->can('view-sensitive', $model)) {
        return '***.***.***-**'; // return masked value instead of decrypting
    }

    return true; // allow decryption
});
```

The callback receives `(Model $model, string $key, array $attributes)` and should:
- Return `true` to allow decryption
- Return a `string` to return a masked value (skips decryption entirely)
- Throw an exception to deny access

## Testing

```bash
composer test
```

## Changelog

Please see [CHANGELOG](CHANGELOG.md) for more information on what has changed recently.

## Security Vulnerabilities

Please review [our security policy](../../security/policy) on how to report security vulnerabilities.

## Credits

- [Lucas Vasconcelos](https://github.com/lumensistemas)
- [All Contributors](../../contributors)

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.
