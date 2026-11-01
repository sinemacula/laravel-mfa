<?php

declare(strict_types = 1);

namespace Tests\Unit\Assurance;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Assurance\Authenticator;
use SineMacula\Laravel\Mfa\Assurance\Combination;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use Tests\Fixtures\Assurance\SessionProofs;

/**
 * Tests for `Combination`: the level, multifactor answer and restriction of a
 * first factor alone or followed by a further proof, its `amr` values, and
 * whether its completing proof is within a maximum age.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Combination::class)]
#[CoversClass(Authenticator::class)]
final class CombinationTest extends TestCase
{
    /**
     * Rows of a combination, then whether it is accepted, multifactor,
     * restricted and phishing-resistant, and its level.
     *
     * @return iterable<string, array{\SineMacula\Laravel\Mfa\Assurance\Combination, bool, bool, bool, bool, \SineMacula\Laravel\Mfa\Enums\AssuranceLevel}>
     */
    public static function provideCombinations(): iterable
    {
        yield 'a password alone' => [Combination::alone(SessionProofs::password()), false, false, false, false, AssuranceLevel::AAL1];
        yield 'an email code alone' => [Combination::alone(SessionProofs::emailCode()), false, false, false, false, AssuranceLevel::UNCLASSIFIED];
        yield 'a phone code alone' => [Combination::alone(SessionProofs::phoneCode()), false, false, true, false, AssuranceLevel::AAL1];
        yield 'a verified passkey alone' => [Combination::alone(SessionProofs::passkeySignIn(SessionProofs::verified())), false, true, false, true, AssuranceLevel::AAL2];
        yield 'a password, then TOTP' => [Combination::after(SessionProofs::password(), SessionProofs::totp()), true, true, false, false, AssuranceLevel::AAL2];
        yield 'a password, then an SMS code' => [Combination::after(SessionProofs::password(), SessionProofs::sms()), true, true, true, false, AssuranceLevel::AAL2];
        yield 'a phone code, then TOTP' => [Combination::after(SessionProofs::phoneCode(), SessionProofs::totp()), true, false, true, false, AssuranceLevel::AAL1];
        yield 'a phone code, then a verified passkey' => [Combination::after(SessionProofs::phoneCode(), SessionProofs::passkey(SessionProofs::verified())), true, true, false, true, AssuranceLevel::AAL2];
        yield 'an external provider, then an email code' => [Combination::after(SessionProofs::externalProvider(), SessionProofs::email()), true, false, false, false, AssuranceLevel::UNCLASSIFIED];
    }

    /**
     * A combination's answers come from the authenticators it relies on.
     *
     * @param  \SineMacula\Laravel\Mfa\Assurance\Combination  $combination
     * @param  bool  $accepted
     * @param  bool  $multifactor
     * @param  bool  $restricted
     * @param  bool  $phishingResistant
     * @param  \SineMacula\Laravel\Mfa\Enums\AssuranceLevel  $level
     * @return void
     */
    #[DataProvider('provideCombinations')]
    public function testAnswersFromItsAuthenticators(Combination $combination, bool $accepted, bool $multifactor, bool $restricted, bool $phishingResistant, AssuranceLevel $level): void
    {
        self::assertSame($accepted, $combination->accepted);
        self::assertSame($multifactor, $combination->multifactor());
        self::assertSame($restricted, $combination->restricted());
        self::assertSame($phishingResistant, $combination->phishingResistant());
        self::assertSame($level, $combination->level());
    }

    /**
     * A combination's `amr` values are its first factor's, then its further
     * proof's, and its time is the further proof's.
     *
     * @return void
     */
    public function testTheFurtherProofCompletesTheCombination(): void
    {
        $further     = SessionProofs::totp(60);
        $combination = Combination::after(SessionProofs::password(3600), $further);

        self::assertSame(['pwd', 'otp'], $combination->amr());
        self::assertSame($further->provedAt, $combination->provedAt);
    }

    /**
     * Rows of a proof's age, a maximum age, and whether the proof is within it.
     *
     * @return iterable<string, array{int, ?int, bool}>
     */
    public static function provideAges(): iterable
    {
        yield 'any age allowed' => [86400, null, true];
        yield 'made now' => [0, 60, true];
        yield 'made at the maximum age' => [60, 60, true];
        yield 'made past the maximum age' => [61, 60, false];
        yield 'made in the future' => [-1, 60, false];
        yield 'made in the future with any age allowed' => [-1, null, true];
    }

    /**
     * A combination is within a maximum age when its completing proof is no
     * older than it and was not made in the future.
     *
     * @param  int  $secondsAgo
     * @param  ?int  $maxAge
     * @param  bool  $within
     * @return void
     */
    #[DataProvider('provideAges')]
    public function testIsWithinAMaximumAge(int $secondsAgo, ?int $maxAge, bool $within): void
    {
        $combination = Combination::alone(SessionProofs::password($secondsAgo));

        self::assertSame($within, $combination->isWithin($maxAge, SessionProofs::now()));
    }
}
