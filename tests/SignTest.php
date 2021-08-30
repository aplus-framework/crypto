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

use Framework\Crypto\Sign;
use PHPUnit\Framework\TestCase;

/**
 * Class SignTest.
 */
final class SignTest extends TestCase
{
    public function testKeyPair() : void
    {
        $keyPair = Sign::makeKeyPair();
        self::assertSame(96, \strlen($keyPair));
        self::assertNotSame($keyPair, Sign::makeKeyPair());
    }

    public function testPublicAndSecretKeys() : void
    {
        $keyPair = Sign::makeKeyPair();
        $publicKey = Sign::makePublicKey($keyPair);
        self::assertSame(32, \strlen($publicKey));
        self::assertSame($publicKey, Sign::makePublicKey($keyPair));
        self::assertNotSame($publicKey, Sign::makePublicKey(Sign::makeKeyPair()));
        $secretKey = Sign::makeSecretKey($keyPair);
        self::assertSame(64, \strlen($secretKey));
        self::assertSame($secretKey, Sign::makeSecretKey($keyPair));
        self::assertNotSame($secretKey, Sign::makeSecretKey(Sign::makeKeyPair()));
    }

    public function testVerifyAndSignature() : void
    {
        $keyPair = Sign::makeKeyPair();
        $publicKey = Sign::makePublicKey($keyPair);
        $secretKey = Sign::makeSecretKey($keyPair);
        $message = 'Ai, aiaiai quiri qui uai';
        $signature = Sign::signature($message, $secretKey);
        self::assertSame($signature, Sign::signature($message, $secretKey));
        self::assertNotSame($signature, Sign::signature($message . '.', $secretKey));
        self::assertTrue(Sign::verify($message, $signature, $publicKey));
        self::assertFalse(Sign::verify($message . '.', $signature, $publicKey));
    }
}
