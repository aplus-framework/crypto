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
 * Trait BoxTrait.
 *
 * @package crypto
 */
trait BoxTrait
{
    public static function makeKeyPair() : string
    {
        return \sodium_crypto_box_keypair();
    }

    public static function makeNonce() : string
    {
        return \random_bytes(\SODIUM_CRYPTO_BOX_NONCEBYTES);
    }

    public static function makeSecretKey(string $keyPair) : string
    {
        return \sodium_crypto_box_secretkey($keyPair);
    }

    public static function makePublicKey(string $keyPair) : string
    {
        return \sodium_crypto_box_publickey($keyPair);
    }
}
