# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 1.x     | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability within this package, please report it via
[GitHub's private vulnerability reporting](https://github.com/lumensistemas/encryption-laravel/security/advisories/new).

**Please do not report security vulnerabilities through public GitHub issues.**

You can expect an initial response within 72 hours. We will work with you to understand
the issue and coordinate a fix before any public disclosure.

## Scope

This package provides field-level encryption using libsodium. Security issues that are
in scope include (but are not limited to):

- Cryptographic weaknesses in the encryption or hashing implementation
- Key material exposure through logs, stack traces, or debug output
- Authentication bypass in the blind index verification
- Insecure defaults in key generation or file permissions
