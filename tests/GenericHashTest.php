<?php
/*
 * This file is part of Aplus Framework Crypto Library.
 *
 * (c) Natan Felles <natanfelles@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */
namespace Tests\Crypto;

use Framework\Crypto\GenericHash;
use PHPUnit\Framework\TestCase;

/**
 * Class GenericHashTest.
 */
final class GenericHashTest extends TestCase
{
    public function testMakeKey() : void
    {
        $key = GenericHash::makeKey();
        self::assertSame(32, \strlen($key));
        self::assertNotSame($key, GenericHash::makeKey());
    }

    public function testKeyException() : void
    {
        $this->expectException(\LengthException::class);
        $this->expectExceptionMessage(
            'GenericHash key must have a length between 16 and 64, 3 given'
        );
        new GenericHash('foo');
    }

    public function testHashLengthException() : void
    {
        $this->expectException(\RangeException::class);
        $this->expectExceptionMessage(
            'Hash length must be a value between 16 and 64, 8 given'
        );
        new GenericHash(GenericHash::makeKey(), 8);
    }

    public function testSignatureAndVerify() : void
    {
        $genericHash = new GenericHash(GenericHash::makeKey());
        $message = 'Hello, friend';
        $signature = $genericHash->signature($message);
        self::assertTrue($genericHash->verify($message, $signature));
        self::assertFalse($genericHash->verify($message . '!', $signature));
        $signature = $genericHash->signature($message, 48);
        self::assertTrue($genericHash->verify($message, $signature, 48));
        self::assertFalse($genericHash->verify($message . '!', $signature, 48));
        $this->expectException(\RangeException::class);
        $genericHash->signature($message, 65);
    }
}
