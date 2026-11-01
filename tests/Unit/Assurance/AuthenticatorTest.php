<?php

declare(strict_types = 1);

namespace Tests\Unit\Assurance;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Assurance\Authenticator;
use SineMacula\Laravel\Mfa\Assurance\ObservedProperties;
use SineMacula\Laravel\Mfa\Enums\KeyProtection;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use Tests\Fixtures\Assurance\SessionProofs;

/**
 * Tests for `Authenticator`: what each kind of proof shows as an authenticator,
 * from its channel and what it observed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Authenticator::class)]
final class AuthenticatorTest extends TestCase
{
    /**
     * Rows of a proof, then whether it is something known, something had, a
     * multi-factor authenticator, restricted and phishing-resistant, and its
     * `amr` values.
     *
     * @return iterable<string, array{\SineMacula\Laravel\Mfa\Proofs\Proof, bool, bool, bool, bool, bool, list<string>}>
     */
    public static function provideProofs(): iterable
    {
        yield 'a password' => [SessionProofs::password(), true, false, false, false, false, ['pwd']];
        yield 'a phone code' => [SessionProofs::phoneCode(), false, true, false, true, false, ['sms']];
        yield 'an email code' => [SessionProofs::emailCode(), false, false, false, false, false, ['otp']];
        yield 'a TOTP code' => [SessionProofs::totp(), false, true, false, false, false, ['otp']];
        yield 'a recovery code' => [SessionProofs::recoveryCode(), false, true, false, false, false, ['otp']];
        yield 'a passkey that verified the person' => [SessionProofs::passkey(SessionProofs::verified()), false, true, true, false, true, ['pop', 'user']];
        yield 'a passkey that did not verify the person' => [SessionProofs::passkey(SessionProofs::unverified()), false, true, false, false, true, ['pop', 'user']];
        yield 'a passkey that observed nothing' => [SessionProofs::passkey(ObservedProperties::none()), false, true, false, false, false, ['pop']];
        yield 'a passkey on a hardware key' => [SessionProofs::passkey(SessionProofs::verified(KeyProtection::HARDWARE)), false, true, true, false, true, ['pop', 'user', 'hwk']];
        yield 'a passkey on a software key' => [
            SessionProofs::passkey(new ObservedProperties(keyProtection: KeyProtection::SOFTWARE)),
            false,
            true,
            false,
            false,
            false,
            ['pop', 'swk'],
        ];
        yield 'an external provider' => [SessionProofs::externalProvider(), false, false, false, false, false, []];
        yield 'an unknown first factor' => [SessionProofs::unknownFirstFactor(), false, false, false, false, false, []];
    }

    /**
     * Each proof is classified from its channel and what it observed.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @param  bool  $knowledge
     * @param  bool  $possession
     * @param  bool  $multiFactor
     * @param  bool  $restricted
     * @param  bool  $phishingResistant
     * @param  list<string>  $amr
     * @return void
     */
    #[DataProvider('provideProofs')]
    public function testClassifiesTheProof(Proof $proof, bool $knowledge, bool $possession, bool $multiFactor, bool $restricted, bool $phishingResistant, array $amr): void
    {
        $authenticator = Authenticator::of($proof);

        self::assertSame($knowledge, $authenticator->knowledge);
        self::assertSame($possession, $authenticator->possession);
        self::assertSame($multiFactor, $authenticator->multiFactor);
        self::assertSame($restricted, $authenticator->restricted);
        self::assertSame($phishingResistant, $authenticator->phishingResistant);
        self::assertSame($amr, $authenticator->amr);
        self::assertSame($knowledge || $possession, $authenticator->establishesLevel());
    }
}
