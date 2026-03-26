<?php

declare(strict_types=1);

namespace LumenSistemas\Encrypt\Tests;

use LumenSistemas\Encrypt\EncryptionServiceProvider;
use Orchestra\Testbench\TestCase as BaseTestCase;

class TestCase extends BaseTestCase
{
    protected function getPackageProviders($app): array
    {
        return [EncryptionServiceProvider::class];
    }
}
