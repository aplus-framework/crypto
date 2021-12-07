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

/**
 * Class Password.
 *
 * @package crypto
 */
class Password
{
    public const LIMIT_INTERACTIVE = 0;
    public const LIMIT_MODERATE = 1;
    public const LIMIT_SENSITIVE = 2;
    protected static int $opsLimit = Password::LIMIT_INTERACTIVE;
    protected static int $memLimit = Password::LIMIT_INTERACTIVE;

    public static function hash(
        string $password,
        int $opslimit = null,
        int $memlimit = null
    ) : string {
        $opslimit ??= static::getOpsLimit();
        $memlimit ??= static::getMemLimit();
        return \sodium_crypto_pwhash_str(
            $password,
            static::getSodiumOpsLimit($opslimit),
            static::getSodiumMemLimit($memlimit)
        );
    }

    public static function needsRehash(
        string $hash,
        int $opslimit = null,
        int $memlimit = null
    ) : bool {
        $opslimit ??= static::getOpsLimit();
        $memlimit ??= static::getMemLimit();
        return \sodium_crypto_pwhash_str_needs_rehash(
            $hash,
            static::getSodiumOpsLimit($opslimit),
            static::getSodiumMemLimit($memlimit)
        );
    }

    public static function verify(string $password, string $hash) : bool
    {
        return \sodium_crypto_pwhash_str_verify($hash, $password);
    }

    public static function setOpsLimit(int $opsLimit) : void
    {
        static::$opsLimit = $opsLimit;
    }

    public static function getOpsLimit() : int
    {
        return static::$opsLimit;
    }

    public static function setMemLimit(int $memLimit) : void
    {
        static::$memLimit = $memLimit;
    }

    public static function getMemLimit() : int
    {
        return static::$memLimit;
    }

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
