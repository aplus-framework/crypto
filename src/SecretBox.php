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
use LengthException;
use SensitiveParameter;
use SodiumException;

/**
 * Class SecretBox.
 *
 * @package crypto
 */
class SecretBox
{
    protected string $key;
    protected string $nonce;

    /**
     * SecretBox constructor.
     *
     * @param string $key
     * @param string $nonce
     *
     * @see SecretBox::makeKey()
     * @see SecretBox::makeNonce()
     *
     * @throws LengthException if key or nonce has not the required length
     */
    public function __construct(
        #[SensitiveParameter]
        string $key,
        #[SensitiveParameter]
        string $nonce
    ) {
        $this->validatedLengths($key, $nonce);
        $this->key = $key;
        $this->nonce = $nonce;
    }

    /**
     * Validates key and nonce.
     *
     * @param string $key
     * @param string $nonce
     *
     * @throws LengthException if key or nonce has not the required length
     */
    protected function validatedLengths(
        #[SensitiveParameter]
        string $key,
        #[SensitiveParameter]
        string $nonce
    ) : void {
        $length = \mb_strlen($key, '8bit');
        if ($length !== \SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
            throw new LengthException(
                'SecretBox key has not the required length (32 bytes), '
                . $length . ' given'
            );
        }
        $length = \mb_strlen($nonce, '8bit');
        if ($length !== \SODIUM_CRYPTO_SECRETBOX_NONCEBYTES) {
            throw new LengthException(
                'SecretBox nonce has not the required length (24 bytes), '
                . $length . ' given'
            );
        }
    }

    /**
     * Encrypts a secret box message.
     *
     * @param string $message
     *
     * @throws SodiumException
     *
     * @return string
     */
    public function encrypt(#[SensitiveParameter] string $message) : string
    {
        return \sodium_crypto_secretbox($message, $this->nonce, $this->key);
    }

    /**
     * Decrypts a secret box message ciphertext.
     *
     * @param string $ciphertext
     *
     * @throws SodiumException
     *
     * @return false|string
     */
    public function decrypt(#[SensitiveParameter] string $ciphertext) : false | string
    {
        return \sodium_crypto_secretbox_open($ciphertext, $this->nonce, $this->key);
    }

    /**
     * Makes a secret box key.
     *
     * @return string
     */
    public static function makeKey() : string
    {
        return \sodium_crypto_secretbox_keygen();
    }

    /**
     * Makes a secret box nonce with the correct length.
     *
     * @throws Exception if fail to get random bytes
     *
     * @return string
     */
    public static function makeNonce() : string
    {
        return \random_bytes(\SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
    }
}
