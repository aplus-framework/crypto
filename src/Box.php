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
use LogicException;

/**
 * Class Box.
 *
 * @package crypto
 */
class Box
{
    use BoxTrait;

    protected string $secretKey;
    protected string $publicKey;
    protected ?string $nonce;

    public function __construct(string $secretKey, string $publicKey, string $nonce = null)
    {
        $this->secretKey = $secretKey;
        $this->publicKey = $publicKey;
        if ($nonce !== null) {
            $this->validateNonce($nonce);
        }
        $this->nonce = $nonce;
    }

    protected function validateNonce(string $nonce) : void
    {
        $length = \mb_strlen($nonce, '8bit');
        if ($length !== \SODIUM_CRYPTO_BOX_NONCEBYTES) {
            throw new LengthException(
                'Box nonce has not the required length (24 bytes), '
                . $length . ' given'
            );
        }
    }

    protected function getNonce(?string $nonce) : string
    {
        if ($nonce !== null) {
            $this->validateNonce($nonce);
            return $nonce;
        }
        if ($this->nonce === null) {
            throw new LogicException('Nonce was not set');
        }
        return $this->nonce;
    }

    protected function getKeyPair() : string
    {
        return \sodium_crypto_box_keypair_from_secretkey_and_publickey(
            $this->secretKey,
            $this->publicKey
        );
    }

    public function encrypt(string $message, string $nonce = null) : string
    {
        return \sodium_crypto_box(
            $message,
            $this->getNonce($nonce),
            $this->getKeyPair()
        );
    }

    public function decrypt(string $ciphertext, string $nonce = null) : false | string
    {
        return \sodium_crypto_box_open(
            $ciphertext,
            $this->getNonce($nonce),
            $this->getKeyPair()
        );
    }
}
