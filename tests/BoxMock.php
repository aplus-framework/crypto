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

use Framework\Crypto\Box;

/**
 * Class BoxMock.
 */
class BoxMock extends Box
{
    public function validateNonce(string $nonce) : void
    {
        parent::validateNonce($nonce);
    }

    public function getNonce(?string $nonce) : string
    {
        return parent::getNonce($nonce);
    }
}
