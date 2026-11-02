<?php

declare(strict_types = 1);

namespace Benchmarks\Support;

use SineMacula\Laravel\Mfa\Proofs\Proof;
use Tests\Fixtures\Assurance\SessionProofs;

/**
 * The sets of proofs the combination and requirement benches evaluate, built on
 * the combination policy's test fixtures, each one session's, against the time
 * those fixtures measure every proof's age from.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class BenchProofs
{
    /** @var int The most proofs one sign-in keeps, the first factor among them. */
    private const int LONG_SESSION = 50;

    /** @var int How far apart a long session's proofs are, in seconds. */
    private const int LONG_SESSION_GAP = 60;

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Only a password first factor.
     *
     * @return list<\SineMacula\Laravel\Mfa\Proofs\Proof>
     */
    public static function firstFactor(): array
    {
        return [SessionProofs::password(60)];
    }

    /**
     * A password first factor and a TOTP code the given seconds ago.
     *
     * @param  int  $secondsAgo
     * @return list<\SineMacula\Laravel\Mfa\Proofs\Proof>
     */
    public static function firstFactorAndTotp(int $secondsAgo = 0): array
    {
        return [SessionProofs::password($secondsAgo + 60), SessionProofs::totp($secondsAgo)];
    }

    /**
     * A password first factor and a verifying passkey, which provide everything
     * a requirement can ask of the default policy short of AAL3.
     *
     * @return list<\SineMacula\Laravel\Mfa\Proofs\Proof>
     */
    public static function firstFactorAndPasskey(): array
    {
        return [SessionProofs::password(60), SessionProofs::passkey(SessionProofs::verified())];
    }

    /**
     * An email first factor and a code to the same address, a channel it cannot
     * be independent of.
     *
     * @return list<\SineMacula\Laravel\Mfa\Proofs\Proof>
     */
    public static function sameChannel(): array
    {
        return [SessionProofs::emailCode(), SessionProofs::email(SessionProofs::EMAIL)];
    }

    /**
     * As many proofs as one sign-in keeps, oldest first.
     *
     * @return list<\SineMacula\Laravel\Mfa\Proofs\Proof>
     */
    public static function longSession(): array
    {
        $further = array_map(
            static fn (int $index): Proof => SessionProofs::totp(($index - 1) * self::LONG_SESSION_GAP),
            range(self::LONG_SESSION - 1, 1),
        );

        return [SessionProofs::password(self::LONG_SESSION * self::LONG_SESSION_GAP), ...$further];
    }
}
