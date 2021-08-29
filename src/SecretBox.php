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

use LengthException;

/**
 * Class SecretBox.
 *
 * @package crypto
 */
class SecretBox
{
    protected string $key;
    protected string $nonce;

    public function __construct(string $key, string $nonce)
    {
        $this->validatedLengths($key, $nonce);
        $this->key = $key;
        $this->nonce = $nonce;
    }

    protected function validatedLengths(string $key, string $nonce) : void
    {
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

    public function encrypt(string $message) : string
    {
        return \sodium_crypto_secretbox($message, $this->nonce, $this->key);
    }

    public function decrypt(string $ciphertext) : false | string
    {
        return \sodium_crypto_secretbox_open($ciphertext, $this->nonce, $this->key);
    }

    public static function makeKey() : string
    {
        return \sodium_crypto_secretbox_keygen();
    }

    public static function makeNonce() : string
    {
        return \random_bytes(\SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
    }
}
