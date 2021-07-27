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

class Password
{
    public const LIMIT_INTERACTIVE = 0;
    public const LIMIT_MODERATE = 1;
    public const LIMIT_SENSITIVE = 2;

    public static function hash(
        string $password,
        int $opslimit = Password::LIMIT_INTERACTIVE,
        int $memlimit = Password::LIMIT_INTERACTIVE
    ) : string {
        $opslimit = static::getOpsLimit($opslimit);
        $memlimit = static::getMemLimit($memlimit);
        return \sodium_crypto_pwhash_str(
            $password,
            $opslimit,
            $memlimit
        );
    }

    public static function needsRehash(
        string $hash,
        int $opslimit = Password::LIMIT_INTERACTIVE,
        int $memlimit = Password::LIMIT_INTERACTIVE
    ) : bool {
        $opslimit = static::getOpsLimit($opslimit);
        $memlimit = static::getMemLimit($memlimit);
        return \sodium_crypto_pwhash_str_needs_rehash(
            $hash,
            $opslimit,
            $memlimit
        );
    }

    public static function verify(string $password, string $hash) : bool
    {
        return \sodium_crypto_pwhash_str_verify($hash, $password);
    }

    protected static function getOpsLimit(int $constant) : int
    {
        return match ($constant) {
            static::LIMIT_INTERACTIVE => \SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
            static::LIMIT_MODERATE => \SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE,
            static::LIMIT_SENSITIVE => \SODIUM_CRYPTO_PWHASH_OPSLIMIT_SENSITIVE,
            default => throw new \InvalidArgumentException(
                'Invalid opslimit value: ' . $constant
            )
        };
    }

    protected static function getMemLimit(int $constant) : int
    {
        return match ($constant) {
            static::LIMIT_INTERACTIVE => \SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
            static::LIMIT_MODERATE => \SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE,
            static::LIMIT_SENSITIVE => \SODIUM_CRYPTO_PWHASH_MEMLIMIT_SENSITIVE,
            default => throw new \InvalidArgumentException(
                'Invalid memlimit value: ' . $constant
            )
        };
    }
}
