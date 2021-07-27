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

class Utils
{
    public static function bin2hex(string $string) : string
    {
        return \sodium_bin2hex($string);
    }

    public static function hex2bin(string $string, string $ignore = '') : string
    {
        return \sodium_hex2bin($string, $ignore);
    }

    public static function base642bin(
        string $string,
        int $id = \SODIUM_BASE64_VARIANT_ORIGINAL,
        string $ignore = ''
    ) : string {
        return \sodium_base642bin($string, $id, $ignore);
    }

    public static function bin2base64(
        string $string,
        int $id = \SODIUM_BASE64_VARIANT_ORIGINAL,
    ) : string {
        return \sodium_bin2base64($string, $id);
    }
}
