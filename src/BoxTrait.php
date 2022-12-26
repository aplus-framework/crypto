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

use Exception;
use SensitiveParameter;
use SodiumException;

/**
 * Trait BoxTrait.
 *
 * @package crypto
 */
trait BoxTrait
{
    /**
     * Makes a keypair.
     *
     * @throws SodiumException
     */
    public static function makeKeyPair() : string
    {
        return \sodium_crypto_box_keypair();
    }

    /**
     * Makes a box nonce with the correct length.
     *
     * @throws Exception if fail to get random bytes
     *
     * @return string
     */
    public static function makeNonce() : string
    {
        return \random_bytes(\SODIUM_CRYPTO_BOX_NONCEBYTES);
    }

    /**
     * Makes the secret key from a keypair.
     *
     * @param string $keyPair
     *
     * @see BoxTrait::makeKeyPair()
     *
     * @throws SodiumException
     *
     * @return string
     */
    public static function makeSecretKey(#[SensitiveParameter] string $keyPair) : string
    {
        return \sodium_crypto_box_secretkey($keyPair);
    }

    /**
     * Makes the public key from a keypair.
     *
     * @param string $keyPair
     *
     * @see BoxTrait::makeKeyPair()
     *
     * @throws SodiumException
     *
     * @return string
     */
    public static function makePublicKey(#[SensitiveParameter] string $keyPair) : string
    {
        return \sodium_crypto_box_publickey($keyPair);
    }
}
