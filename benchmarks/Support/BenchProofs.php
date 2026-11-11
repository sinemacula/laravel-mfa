<?php

declare(strict_types = 1);

namespace Benchmarks\Support;

use SineMacula\Laravel\Mfa\Proofs\Proof;
use Tests\Fixtures\Assurance\SessionProofs;

/**
 * Session proof sets for the combination and requirement benches.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class BenchProofs
{
    /** @var int The most proofs one sign-in keeps, first factor included. */
    private const int LONG_SESSION = 50;

    /** @var int Seconds between a long session's proofs. */
    private const int LONG_SESSION_GAP = 60;

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * @return list<\SineMacula\Laravel\Mfa\Proofs\Proof>
     */
    public static function firstFactor(): array
    {
        return [SessionProofs::password(60)];
    }

    /**
     * @param  int  $secondsAgo
     * @return list<\SineMacula\Laravel\Mfa\Proofs\Proof>
     */
    public static function firstFactorAndTotp(int $secondsAgo = 0): array
    {
        return [SessionProofs::password($secondsAgo + 60), SessionProofs::totp($secondsAgo)];
    }

    /**
     * Everything the default policy can require short of AAL3.
     *
     * @return list<\SineMacula\Laravel\Mfa\Proofs\Proof>
     */
    public static function firstFactorAndPasskey(): array
    {
        return [SessionProofs::password(60), SessionProofs::passkey(SessionProofs::verified())];
    }

    /**
     * An email first factor and a code to the same, dependent, address.
     *
     * @return list<\SineMacula\Laravel\Mfa\Proofs\Proof>
     */
    public static function sameChannel(): array
    {
        return [SessionProofs::emailCode(), SessionProofs::email(SessionProofs::EMAIL)];
    }

    /**
     * Oldest first.
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
