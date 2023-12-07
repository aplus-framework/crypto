<?php
/*
 * This file is part of Aplus Framework Crypto Library.
 *
 * (c) Natan Felles <natanfelles@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */
namespace Tests\Crypto;

use Framework\Crypto\Utils;
use PHPUnit\Framework\TestCase;

final class UtilsTest extends TestCase
{
    public function testHexBin() : void
    {
        $bin = 'foo';
        $hex = Utils::bin2hex($bin);
        self::assertSame(6, \strlen($hex));
        self::assertSame($bin, Utils::hex2bin($hex));
    }

    public function testBase64Bin() : void
    {
        $bin = 'foo';
        $base64 = Utils::bin2base64($bin);
        self::assertSame(4, \strlen($base64));
        self::assertSame($bin, Utils::base642bin($base64));
    }
}
