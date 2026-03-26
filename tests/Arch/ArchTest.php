<?php

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Facade;
use LumenSistemas\Encrypt\Encrypter;

arch()->preset()->php();

arch()->preset()->security();

it('will not use debugging functions')
    ->expect(['dd', 'dump', 'ray', 'var_dump', 'print_r'])
    ->not->toBeUsed();

it('source classes use strict types')
    ->expect('LumenSistemas\\Encrypt')
    ->toUseStrictTypes();

it('value objects are final and readonly')
    ->expect('LumenSistemas\\Encrypt\\ValueObjects')
    ->toBeFinal()
    ->toBeReadonly();

it('exceptions extend Exception and have the Exception suffix')
    ->expect('LumenSistemas\\Encrypt\\Exceptions')
    ->toExtend(Exception::class)
    ->toHaveSuffix('Exception');

it('facades extend the Laravel Facade base class')
    ->expect('LumenSistemas\\Encrypt\\Facades')
    ->toExtend(Facade::class);

it('console commands extend Command and have the Command suffix')
    ->expect('LumenSistemas\\Encrypt\\Console')
    ->toExtend(Command::class)
    ->toHaveSuffix('Command');

it('core classes do not depend on Laravel')
    ->expect([Encrypter::class, 'LumenSistemas\\Encrypt\\ValueObjects'])
    ->not->toUse('Illuminate\\');
