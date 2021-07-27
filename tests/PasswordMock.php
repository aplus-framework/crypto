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

use Framework\Crypto\Password;

class PasswordMock extends Password
{
    public static function getMemLimit(int $constant) : int
    {
        return parent::getMemLimit($constant);
    }

    public static function getOpsLimit(int $constant) : int
    {
        return parent::getOpsLimit($constant);
    }
}
