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

use Framework\Crypto\BoxSeal;
use PHPUnit\Framework\TestCase;

/**
 * Class BoxSealTest.
 */
final class BoxSealTest extends TestCase
{
    public function testEncryptAndDecrypt() : void
    {
        $keyPair = BoxSeal::makeKeyPair();
        $publicKey = BoxSeal::makePublicKey($keyPair);
        $message = 'Expect us!';
        $ciphertext = BoxSeal::encrypt($message, $publicKey);
        self::assertSame($message, BoxSeal::decrypt($ciphertext, $keyPair));
    }
}
