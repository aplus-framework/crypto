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
 * Class BoxSeal.
 *
 * @package crypto
 */
class BoxSeal
{
    use BoxTrait;

    public static function encrypt(string $message, string $publicKey) : string
    {
        return \sodium_crypto_box_seal($message, $publicKey);
    }

    public static function decrypt(string $ciphertext, string $keyPair) : false|string
    {
        return \sodium_crypto_box_seal_open($ciphertext, $keyPair);
    }
}
