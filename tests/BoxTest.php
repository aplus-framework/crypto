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

use Framework\Crypto\Box;
use PHPUnit\Framework\TestCase;

/**
 * Class BoxTest.
 */
final class BoxTest extends TestCase
{
    public function testMakeKeyPair() : void
    {
        $keyPair = Box::makeKeyPair();
        self::assertSame(64, \strlen($keyPair));
        self::assertNotSame($keyPair, Box::makeKeyPair());
    }

    public function testPublicAndSecretKeys() : void
    {
        $keyPair = Box::makeKeyPair();
        $publicKey = Box::makePublicKey($keyPair);
        self::assertSame(32, \strlen($publicKey));
        self::assertSame($publicKey, Box::makePublicKey($keyPair));
        self::assertNotSame($publicKey, Box::makePublicKey(Box::makeKeyPair()));
        $secretKey = Box::makeSecretKey($keyPair);
        self::assertSame(32, \strlen($secretKey));
        self::assertSame($secretKey, Box::makeSecretKey($keyPair));
        self::assertNotSame($secretKey, Box::makeSecretKey(Box::makeKeyPair()));
    }

    public function testMakeNonce() : void
    {
        $nonce = Box::makeNonce();
        self::assertSame(24, \strlen($nonce));
        self::assertNotSame($nonce, Box::makeNonce());
    }

    public function testEncryptAndDecrypt() : void
    {
        $user1KeyPair = Box::makeKeyPair();
        $user1PublicKey = Box::makePublicKey($user1KeyPair);
        $user1SecretKey = Box::makeSecretKey($user1KeyPair);
        $user2KeyPair = Box::makeKeyPair();
        $user2PublicKey = Box::makePublicKey($user2KeyPair);
        $user2SecretKey = Box::makeSecretKey($user2KeyPair);
        $nonce1 = Box::makeNonce();
        $user1Box = new Box($user1SecretKey, $user2PublicKey, $nonce1);
        $messageFromUser1 = 'What is you name?';
        $ciphertext1 = $user1Box->encrypt($messageFromUser1);
        self::assertSame($messageFromUser1, $user1Box->decrypt($ciphertext1));
        $user2Box = new Box($user2SecretKey, $user1PublicKey, $nonce1);
        self::assertSame($messageFromUser1, $user2Box->decrypt($ciphertext1));
        $nonce2 = Box::makeNonce();
        $user2Box = new Box($user2SecretKey, $user1PublicKey, $nonce2);
        $messageFromUser2 = 'John';
        $ciphertext2 = $user2Box->encrypt($messageFromUser2);
        self::assertSame($messageFromUser2, $user2Box->decrypt($ciphertext2));
        $user1Box = new Box($user1SecretKey, $user2PublicKey, $nonce2);
        self::assertSame($messageFromUser2, $user1Box->decrypt($ciphertext2));
    }

    public function testValidateNonce() : void
    {
        $keyPair = Box::makeKeyPair();
        $publicKey = Box::makePublicKey($keyPair);
        $secretKey = Box::makeSecretKey($keyPair);
        $box = new BoxMock($secretKey, $publicKey);
        $box->validateNonce(Box::makeNonce());
        $this->expectException(\LengthException::class);
        $this->expectExceptionMessage(
            'Box nonce has not the required length (24 bytes), 3 given'
        );
        $box->validateNonce('foo');
    }

    public function testGetNonce() : void
    {
        $keyPair = Box::makeKeyPair();
        $publicKey = Box::makePublicKey($keyPair);
        $secretKey = Box::makeSecretKey($keyPair);
        $nonce = Box::makeNonce();
        $box = new BoxMock($secretKey, $publicKey, $nonce);
        self::assertSame($nonce, $box->getNonce(null));
        self::assertSame($nonce, $box->getNonce($nonce));
        $box = new BoxMock($secretKey, $publicKey);
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('Nonce was not set');
        self::assertSame($nonce, $box->getNonce(null));
    }
}
