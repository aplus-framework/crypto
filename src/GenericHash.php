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
use SensitiveParameter;
use SodiumException;

/**
 * Class GenericHash.
 *
 * @package crypto
 */
class GenericHash
{
    protected string $key;
    protected int $hashLength = \SODIUM_CRYPTO_GENERICHASH_BYTES;

    /**
     * GenericHash constructor.
     *
     * @param string $key
     * @param int $hashLength
     *
     * @see GenericHash::makeKey()
     *
     * @throws LengthException if key length is not between 16 and 64
     * @throws RangeException if the hashLength value is not in the range 16 to 64
     */
    public function __construct(
        #[SensitiveParameter]
        string $key,
        int $hashLength = \SODIUM_CRYPTO_GENERICHASH_BYTES
    ) {
        $this->validateKey($key);
        $this->validateHashLength($hashLength);
        $this->key = $key;
        $this->hashLength = $hashLength;
    }

    /**
     * Validates a key.
     *
     * @param string $key
     *
     * @throws LengthException if key length is not between 16 and 64
     */
    protected function validateKey(#[SensitiveParameter] string $key) : void
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

    /**
     * Validates a hash length.
     *
     * @param int $length
     *
     * @throws RangeException if the length value is not in the range 16 to 64
     */
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

    /**
     * Gets a message signature.
     *
     * @param string $message
     * @param int|null $hashLength A custom hash length or null to use the length set in
     * the constructor
     *
     * @throws RangeException if the hashLength is set and is not in the range 16 to 64
     * @throws SodiumException
     *
     * @return string
     */
    public function signature(
        #[SensitiveParameter]
        string $message,
        int $hashLength = null
    ) : string {
        return Utils::bin2base64(
            $this->makeHash($message, $hashLength),
            \SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING
        );
    }

    /**
     * Verifies if a message matches a signature.
     *
     * @param string $message
     * @param string $signature
     * @param int|null $hashLength A custom hash length or null to use the length set in
     * the constructor
     *
     * @throws RangeException if the hashLength is set and is not in the range 16 to 64
     * @throws SodiumException
     *
     * @return bool
     */
    public function verify(
        #[SensitiveParameter]
        string $message,
        #[SensitiveParameter]
        string $signature,
        int $hashLength = null
    ) : bool {
        return \hash_equals(
            $this->makeHash($message, $hashLength),
            Utils::base642bin($signature, \SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING)
        );
    }

    /**
     * Makes a hash to a message.
     *
     * @param string $message
     * @param int|null $length A custom length or null to use the length set in
     * the constructor
     *
     * @throws RangeException if the length is set and is not in the range 16 to 64
     * @throws SodiumException
     *
     * @return string
     */
    protected function makeHash(#[SensitiveParameter] string $message, int $length = null) : string
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

    /**
     * Makes a key.
     *
     * @return string
     */
    public static function makeKey() : string
    {
        return \sodium_crypto_generichash_keygen();
    }
}
