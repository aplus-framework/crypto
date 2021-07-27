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
use PHPUnit\Framework\TestCase;

final class PasswordTest extends TestCase
{
    protected Password $sample;

    protected function setUp() : void
    {
        $this->sample = new Password();
    }

    public function testSample() : void
    {
        self::assertSame(
            'Framework\Crypto\Password::test',
            $this->sample->test()
        );
    }
}
