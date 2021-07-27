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

use Framework\Crypto\Password;
use PHPUnit\Framework\TestCase;

final class PasswordTest extends TestCase
{
    public function testHash() : void
    {
        $password = 'iloveyou';
        $hash = Password::hash($password);
        self::assertNotSame($password, $hash);
        self::assertNotSame($hash, Password::hash($password));
        self::assertSame(97, \strlen($hash));
    }

    public function testNeedsRehash() : void
    {
        $password = 'iloveyou';
        $hash = Password::hash($password);
        self::assertFalse(Password::needsRehash($hash));
        self::assertTrue(Password::needsRehash($hash, Password::LIMIT_MODERATE));
        $hash = Password::hash($password, Password::LIMIT_MODERATE);
        self::assertTrue(Password::needsRehash($hash));
        self::assertFalse(Password::needsRehash($hash, Password::LIMIT_MODERATE));
    }

    public function testVerify() : void
    {
        $password = 'iloveyou';
        $hash = Password::hash($password);
        self::assertTrue(Password::verify($password, $hash));
        self::assertFalse(Password::verify('secret', $hash));
    }

    public function testGetOpsLimit() : void
    {
        self::assertSame(
            \SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
            PasswordMock::getOpsLimit(Password::LIMIT_INTERACTIVE)
        );
        self::assertSame(
            \SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE,
            PasswordMock::getOpsLimit(Password::LIMIT_MODERATE)
        );
        self::assertSame(
            \SODIUM_CRYPTO_PWHASH_OPSLIMIT_SENSITIVE,
            PasswordMock::getOpsLimit(Password::LIMIT_SENSITIVE)
        );
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid opslimit value: 369');
        PasswordMock::getOpsLimit(369);
    }

    public function testGetMemLimit() : void
    {
        self::assertSame(
            \SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
            PasswordMock::getMemLimit(Password::LIMIT_INTERACTIVE)
        );
        self::assertSame(
            \SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE,
            PasswordMock::getMemLimit(Password::LIMIT_MODERATE)
        );
        self::assertSame(
            \SODIUM_CRYPTO_PWHASH_MEMLIMIT_SENSITIVE,
            PasswordMock::getMemLimit(Password::LIMIT_SENSITIVE)
        );
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid memlimit value: 369');
        PasswordMock::getMemLimit(369);
    }
}
