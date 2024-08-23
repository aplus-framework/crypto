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

use InvalidArgumentException;
use SensitiveParameter;
use SodiumException;

/**
 * Class Password.
 *
 * @package crypto
 */
class Password
{
    /**
     * Used to set operations or memory limit as interactive.
     * It enables the use of 2 CPU operations or 64 MB RAM.
     */
    public const int LIMIT_INTERACTIVE = 0;
    /**
     * Used to set operations or memory limit as moderate.
     * It enables the use of 3 CPU operations or 256 MB RAM.
     */
    public const int LIMIT_MODERATE = 1;
    /**
     * Used to set operations or memory limit as sensitive.
     * It enables the use of 4 CPU operations or 1 GB RAM.
     */
    public const int LIMIT_SENSITIVE = 2;
    protected static int $opsLimit = Password::LIMIT_INTERACTIVE;
    protected static int $memLimit = Password::LIMIT_INTERACTIVE;

    /**
     * Makes a password hash.
     *
     * @param string $password
     * @param int|null $opslimit A Password constant or null to use the default
     * set for opslimit
     * @param int|null $memlimit A Password constant or null to use the default
     * set for memlimit. Typically, it should be paired with the opslimit value
     *
     * @see Password::LIMIT_INTERACTIVE
     * @see Password::LIMIT_MODERATE
     * @see Password::LIMIT_SENSITIVE
     *
     * @throws SodiumException
     *
     * @return string
     */
    public static function hash(
        #[SensitiveParameter]
        string $password,
        ?int $opslimit = null,
        ?int $memlimit = null
    ) : string {
        $opslimit ??= static::getOpsLimit();
        $memlimit ??= static::getMemLimit();
        return \sodium_crypto_pwhash_str(
            $password,
            static::getSodiumOpsLimit($opslimit),
            static::getSodiumMemLimit($memlimit)
        );
    }

    /**
     * Checks if a hash needs to be rehashed based on the ops and mem limits.
     *
     * @param string $hash
     * @param int|null $opslimit A Password constant or null to use the default
     * set for opslimit
     * @param int|null $memlimit A Password constant or null to use the default
     * set for memlimit
     *
     * @return bool
     */
    public static function needsRehash(
        #[SensitiveParameter]
        string $hash,
        ?int $opslimit = null,
        ?int $memlimit = null
    ) : bool {
        $opslimit ??= static::getOpsLimit();
        $memlimit ??= static::getMemLimit();
        return \sodium_crypto_pwhash_str_needs_rehash(
            $hash,
            static::getSodiumOpsLimit($opslimit),
            static::getSodiumMemLimit($memlimit)
        );
    }

    /**
     * Verifies a password against a hash.
     *
     * @param string $password
     * @param string $hash
     *
     * @throws SodiumException
     *
     * @return bool
     */
    public static function verify(
        #[SensitiveParameter]
        string $password,
        #[SensitiveParameter]
        string $hash
    ) : bool {
        return \sodium_crypto_pwhash_str_verify($hash, $password);
    }

    /**
     * Sets the default Password operations limit.
     *
     * @param int $opsLimit A Password constant value
     *
     * @see Password::LIMIT_INTERACTIVE
     * @see Password::LIMIT_MODERATE
     * @see Password::LIMIT_SENSITIVE
     */
    public static function setOpsLimit(int $opsLimit) : void
    {
        static::$opsLimit = $opsLimit;
    }

    /**
     * Gets the default Password operations limit constant value.
     *
     * @return int
     */
    public static function getOpsLimit() : int
    {
        return static::$opsLimit;
    }

    /**
     * Sets the default Password memory limit.
     *
     * @param int $memLimit A Password constant value. Typically, it should be
     * paired with the opslimit value
     *
     * @see Password::LIMIT_INTERACTIVE
     * @see Password::LIMIT_MODERATE
     * @see Password::LIMIT_SENSITIVE
     */
    public static function setMemLimit(int $memLimit) : void
    {
        static::$memLimit = $memLimit;
    }

    /**
     * Gets the default Password memory limit constant value.
     *
     * @return int
     */
    public static function getMemLimit() : int
    {
        return static::$memLimit;
    }

    /**
     * Gets an appropriate sodium operations limit value from a Password constant.
     *
     * @param int $constant
     *
     * @throws InvalidArgumentException if constant value is invalid
     *
     * @return int
     */
    protected static function getSodiumOpsLimit(int $constant) : int
    {
        return match ($constant) {
            static::LIMIT_INTERACTIVE => \SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
            static::LIMIT_MODERATE => \SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE,
            static::LIMIT_SENSITIVE => \SODIUM_CRYPTO_PWHASH_OPSLIMIT_SENSITIVE,
            default => throw new InvalidArgumentException(
                'Invalid opslimit value: ' . $constant
            )
        };
    }

    /**
     * Gets an appropriate sodium memory limit value from a Password constant.
     *
     * @param int $constant
     *
     * @throws InvalidArgumentException if constant value is invalid
     *
     * @return int
     */
    protected static function getSodiumMemLimit(int $constant) : int
    {
        return match ($constant) {
            static::LIMIT_INTERACTIVE => \SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
            static::LIMIT_MODERATE => \SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE,
            static::LIMIT_SENSITIVE => \SODIUM_CRYPTO_PWHASH_MEMLIMIT_SENSITIVE,
            default => throw new InvalidArgumentException(
                'Invalid memlimit value: ' . $constant
            )
        };
    }
}
