<?php
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
 * Class HiddenString.
 */
class HiddenString
{
    protected ?string $string;

    public function __construct(string $string)
    {
        $this->string = static::copy($string);
    }

    public function __destruct()
    {
        \sodium_memzero($this->string);
        $this->string = null;
    }

    public function getString() : string
    {
        return static::copy($this->string);
    }

    public function equals(HiddenString $to) : bool
    {
        return \hash_equals(
            $this->getString(),
            $to->getString()
        );
    }

    public static function copy(string $string) : string
    {
        $length = \mb_strlen($string, '8bit');
        $chunk = $length >> 1;
        if ($chunk < 1) {
            $chunk = 1;
        }
        $result = '';
        for ($i = 0; $i < $length; $i += $chunk) {
            $result .= \mb_substr($string, $i, $chunk, '8bit');
        }
        return $result;
    }
}
