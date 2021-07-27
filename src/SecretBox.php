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

class SecretBox
{
    protected string $key;
    protected string $nonce;

    public function __construct(string $key, string $nonce)
    {
        $this->key = $key;
        $this->nonce = $nonce;
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
