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

use SensitiveParameter;
use SodiumException;

/**
 * Class BoxSeal.
 *
 * @package crypto
 */
class BoxSeal
{
    use BoxTrait;

    /**
     * Encrypts a message with an anonymous public key.
     *
     * @param string $message
     * @param string $publicKey
     *
     * @see BoxTrait::makePublicKey()
     *
     * @throws SodiumException
     *
     * @return string
     */
    public static function encrypt(
        #[SensitiveParameter] string $message,
        #[SensitiveParameter] string $publicKey
    ) : string {
        return \sodium_crypto_box_seal($message, $publicKey);
    }

    /**
     * Decrypts a message ciphertext.
     *
     * @param string $ciphertext
     * @param string $keyPair
     *
     * @see BoxTrait::makeKeyPair()
     *
     * @throws SodiumException
     *
     * @return false|string The message or false if the ciphertext could not be
     * decrypted
     */
    public static function decrypt(
        #[SensitiveParameter] string $ciphertext,
        #[SensitiveParameter]  string $keyPair
    ) : false | string {
        return \sodium_crypto_box_seal_open($ciphertext, $keyPair);
    }
}
