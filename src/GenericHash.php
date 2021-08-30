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
use RangeException;

/**
 * Class GenericHash.
 *
 * @package crypto
 */
class GenericHash
{
    protected string $key;
    protected int $hashLength = \SODIUM_CRYPTO_GENERICHASH_BYTES;

    public function __construct(string $key, int $hashLength = \SODIUM_CRYPTO_GENERICHASH_BYTES)
    {
        $this->validateKey($key);
        $this->validateHashLength($hashLength);
        $this->key = $key;
        $this->hashLength = $hashLength;
    }

    protected function validateKey(string $key) : void
    {
        $length = \mb_strlen($key, '8bit');
        if ($length < \SODIUM_CRYPTO_GENERICHASH_KEYBYTES_MIN
            || $length > \SODIUM_CRYPTO_GENERICHASH_KEYBYTES_MAX
        ) {
            throw new LengthException(
                'GenericHash key must have a length between '
                . \SODIUM_CRYPTO_GENERICHASH_KEYBYTES_MIN . ' and '
                . \SODIUM_CRYPTO_GENERICHASH_KEYBYTES_MAX . ', '
                . $length . ' given'
            );
        }
    }

    protected function validateHashLength(int $length) : void
    {
        if ($length < \SODIUM_CRYPTO_GENERICHASH_BYTES_MIN
            || $length > \SODIUM_CRYPTO_GENERICHASH_BYTES_MAX
        ) {
            throw new RangeException(
                'Hash length must be a value between ' . \SODIUM_CRYPTO_GENERICHASH_BYTES_MIN
                . ' and ' . \SODIUM_CRYPTO_GENERICHASH_BYTES_MAX . ', '
                . $length . ' given'
            );
        }
    }

    public function signature(string $message, int $hashLength = null) : string
    {
        return Utils::bin2base64(
            $this->makeHash($message, $hashLength),
            \SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING
        );
    }

    public function verify(string $message, string $signature, int $hashLength = null) : bool
    {
        return \hash_equals(
            $this->makeHash($message, $hashLength),
            Utils::base642bin($signature, \SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING)
        );
    }

    protected function makeHash(string $message, int $length = null) : string
    {
        if ($length !== null) {
            $this->validateHashLength($length);
        }
        return \sodium_crypto_generichash(
            $message,
            $this->key,
            $length ?? $this->hashLength
        );
    }

    public static function makeKey() : string
    {
        return \sodium_crypto_generichash_keygen();
    }
}
