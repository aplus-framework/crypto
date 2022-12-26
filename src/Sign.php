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

use SodiumException;

/**
 * Class Sign.
 *
 * @package crypto
 */
class Sign
{
    /**
     * Makes a keypair.
     *
     * @throws SodiumException
     *
     * @return string
     */
    public static function makeKeyPair() : string
    {
        return \sodium_crypto_sign_keypair();
    }

    /**
     * Makes the secret key from a keypair.
     *
     * @param string $keyPair
     *
     * @see Sign::makeKeyPair()
     *
     * @throws SodiumException
     *
     * @return string
     */
    public static function makeSecretKey(string $keyPair) : string
    {
        return \sodium_crypto_sign_secretkey($keyPair); // @phpstan-ignore-line
    }

    /**
     * Makes the public key from a keypair.
     *
     * @param string $keyPair
     *
     * @see Sign::makeKeyPair()
     *
     * @throws SodiumException
     *
     * @return string
     */
    public static function makePublicKey(string $keyPair) : string
    {
        return \sodium_crypto_sign_publickey($keyPair); // @phpstan-ignore-line
    }

    /**
     * Gets the digital signature (detached) from a message with a secret key.
     *
     * @param string $message
     * @param string $secretKey
     *
     * @see Sign::makeSecretKey()
     *
     * @throws SodiumException
     *
     * @return string
     */
    public static function signature(string $message, string $secretKey) : string
    {
        return \sodium_crypto_sign_detached($message, $secretKey); // @phpstan-ignore-line
    }

    /**
     * Verifies if a message has a valid signature.
     *
     * @param string $message
     * @param string $signature
     * @param string $publicKey
     *
     * @see Sign::makePublicKey()
     * @see Sign::signature()
     *
     * @throws SodiumException
     *
     * @return bool
     */
    public static function verify(
        string $message,
        string $signature,
        string $publicKey
    ) : bool {
        return \sodium_crypto_sign_verify_detached($signature, $message, $publicKey); // @phpstan-ignore-line
    }
}
