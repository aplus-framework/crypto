<?php declare(strict_types=1);
/*
 * This file is part of Aplus Framework Crypto Library.
 *
 * (c) Natan Felles <natanfelles@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */
namespace Framework\Crypto;

/**
 * Class Sign.
 *
 * @package crypto
 */
class Sign
{
    public static function makeKeyPair() : string
    {
        return \sodium_crypto_sign_keypair();
    }

    public static function makeSecretKey(string $keyPair) : string
    {
        return \sodium_crypto_sign_secretkey($keyPair);
    }

    public static function makePublicKey(string $keyPair) : string
    {
        return \sodium_crypto_sign_publickey($keyPair);
    }

    public static function signature(string $message, string $secretKey) : string
    {
        return \sodium_crypto_sign_detached($message, $secretKey);
    }

    public static function verify(
        string $message,
        string $signature,
        string $publicKey
    ) : bool {
        return \sodium_crypto_sign_verify_detached($signature, $message, $publicKey);
    }
}
