<?php namespace Tests\Crypto;

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
