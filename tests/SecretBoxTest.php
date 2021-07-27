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

use Framework\Crypto\SecretBox;
use PHPUnit\Framework\TestCase;

final class SecretBoxTest extends TestCase
{
    public function testMakeKey() : void
    {
        $key = SecretBox::makeKey();
        self::assertSame(32, \strlen($key));
        self::assertNotSame($key, SecretBox::makeKey());
    }

    public function testMakeNonce() : void
    {
        $nonce = SecretBox::makeNonce();
        self::assertSame(24, \strlen($nonce));
        self::assertNotSame($nonce, SecretBox::makeNonce());
    }

    public function testEncryptDecrypt() : void
    {
        $key = SecretBox::makeKey();
        $nonce = SecretBox::makeNonce();
        $secretBox = new SecretBox($key, $nonce);
        $message = 'Hello, Sodium!';
        $ciphertext = $secretBox->encrypt($message);
        self::assertNotSame($message, $ciphertext);
        self::assertSame($message, $secretBox->decrypt($ciphertext));
    }

    public function testKeyException() : void
    {
        $this->expectException(\LengthException::class);
        $this->expectExceptionMessage(
            'SecretBox key has not the required length (32 bytes), 3 given'
        );
        new SecretBox('foo', SecretBox::makeNonce());
    }

    public function testNonceException() : void
    {
        $this->expectException(\LengthException::class);
        $this->expectExceptionMessage(
            'SecretBox nonce has not the required length (24 bytes), 4 given'
        );
        new SecretBox(SecretBox::makeKey(), 'bazz');
    }
}
