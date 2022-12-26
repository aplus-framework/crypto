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
use SensitiveParameter;
use SodiumException;

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

    /**
     * Box constructor.
     *
     * @param string $secretKey
     * @param string $publicKey
     * @param string|null $nonce
     *
     * @see BoxTrait::makePublicKey()
     * @see BoxTrait::makeSecretKey()
     * @see BoxTrait::makeNonce()
     *
     * @throws LengthException if nonce is set has not the required length
     */
    public function __construct(
        #[SensitiveParameter] string $secretKey,
        #[SensitiveParameter] string $publicKey,
        #[SensitiveParameter] string $nonce = null
    ) {
        $this->secretKey = $secretKey;
        $this->publicKey = $publicKey;
        if ($nonce !== null) {
            $this->validateNonce($nonce);
        }
        $this->nonce = $nonce;
    }

    /**
     * Validates a nonce.
     *
     * @param string $nonce
     *
     * @throws LengthException if nonce has not the required length
     */
    protected function validateNonce(#[SensitiveParameter] string $nonce) : void
    {
        $length = \mb_strlen($nonce, '8bit');
        if ($length !== \SODIUM_CRYPTO_BOX_NONCEBYTES) {
            throw new LengthException(
                'Box nonce has not the required length (24 bytes), '
                . $length . ' given'
            );
        }
    }

    /**
     * @param string|null $nonce
     *
     * @throws LengthException if nonce is set and has not the required length
     * @throws LogicException if nonce param is null and nonce was not set in
     * constructor
     *
     * @return string
     */
    protected function getNonce(#[SensitiveParameter] ?string $nonce) : string
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

    /**
     * Gets the keypair from the secret and public keys.
     *
     * @throws SodiumException
     *
     * @return string
     */
    protected function getKeyPair() : string
    {
        return \sodium_crypto_box_keypair_from_secretkey_and_publickey(
            $this->secretKey,
            $this->publicKey
        );
    }

    /**
     * Encrypts a box message.
     *
     * @param string $message
     * @param string|null $nonce The message nonce or null to use the nonce set
     * int the constructor
     *
     * @throws LengthException if nonce is set and has not the required length
     * @throws LogicException if nonce param is null and nonce was not set in
     * the constructor
     * @throws SodiumException
     *
     * @return string
     */
    public function encrypt(
        #[SensitiveParameter] string $message,
        #[SensitiveParameter] string $nonce = null
    ) : string {
        return \sodium_crypto_box(
            $message,
            $this->getNonce($nonce),
            $this->getKeyPair()
        );
    }

    /**
     * Decrypts a box message ciphertext.
     *
     * @param string $ciphertext
     * @param string|null $nonce The message nonce or null to use the nonce set
     * int the constructor
     *
     * @throws LengthException if nonce is set and has not the required length
     * @throws LogicException if nonce param is null and nonce was not set in
     * the constructor
     * @throws SodiumException
     *
     * @return false|string
     */
    public function decrypt(
        #[SensitiveParameter] string $ciphertext,
        #[SensitiveParameter] string $nonce = null
    ) : false | string {
        return \sodium_crypto_box_open(
            $ciphertext,
            $this->getNonce($nonce),
            $this->getKeyPair()
        );
    }
}
