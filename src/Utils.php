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
 * Class Utils.
 *
 * @package crypto
 */
class Utils
{
    /**
     * Converts a binary string to hexadecimal.
     *
     * @param string $string
     *
     * @throws SodiumException
     *
     * @return string The hexadecimal string
     */
    public static function bin2hex(string $string) : string
    {
        return \sodium_bin2hex($string);
    }

    /**
     * Converts a hexadecimal string to binary.
     *
     * @param string $string
     * @param string $ignore
     *
     * @throws SodiumException
     *
     * @return string The binary string
     */
    public static function hex2bin(string $string, string $ignore = '') : string
    {
        return \sodium_hex2bin($string, $ignore);
    }

    /**
     * Converts a base64 string to binary.
     *
     * @param string $string
     * @param int $id
     * @param string $ignore
     *
     * @throws SodiumException
     *
     * @return string The binary string
     */
    public static function base642bin(
        string $string,
        int $id = \SODIUM_BASE64_VARIANT_ORIGINAL,
        string $ignore = ''
    ) : string {
        return \sodium_base642bin($string, $id, $ignore);
    }

    /**
     * Converts a binary string to base64.
     *
     * @param string $string
     * @param int $id
     *
     * @throws SodiumException
     *
     * @return string The base64 encoded string
     */
    public static function bin2base64(
        string $string,
        int $id = \SODIUM_BASE64_VARIANT_ORIGINAL,
    ) : string {
        return \sodium_bin2base64($string, $id);
    }
}
