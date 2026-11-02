<?php

declare(strict_types = 1);

namespace Tests\Unit\Passkeys;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Assurance\ObservedProperties;
use SineMacula\Laravel\Mfa\Enums\FactorStatus;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyAssociationResult;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyRegistration;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Secrets\RevealedSecret;

/**
 * Unit tests for `PasskeyRegistration`, the passkey an authentication layer
 * hands the change gate, and `PasskeyAssociationResult`, what associating it
 * made.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PasskeyRegistration::class)]
#[CoversClass(PasskeyAssociationResult::class)]
final class PasskeyRegistrationTest extends TestCase
{
    /**
     * A registration keeps its credential, what it observed and its binding.
     *
     * @return void
     */
    public function testKeepsItsParts(): void
    {
        $properties   = new ObservedProperties(userPresence: true, userVerification: true);
        $binding      = self::binding(Purpose::ENROLLMENT);
        $registration = new PasskeyRegistration('Y3JlZGVudGlhbC1vbmU', $properties, $binding);

        self::assertSame('Y3JlZGVudGlhbC1vbmU', $registration->credentialId);
        self::assertSame($properties, $registration->properties);
        self::assertSame($binding, $registration->binding);
    }

    /**
     * A credential id that is not canonical is refused.
     *
     * @return void
     */
    public function testRefusesANonCanonicalCredentialId(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new PasskeyRegistration('Y3JlZGVudGlhbC1vbmU=', ObservedProperties::none(), self::binding(Purpose::ENROLLMENT));
    }

    /**
     * A registration bound for anything but enrolment is refused.
     *
     * @return void
     */
    public function testRefusesABindingForAnotherPurpose(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A passkey registration is bound for [enrollment], not [sign_in].');

        new PasskeyRegistration('Y3JlZGVudGlhbC1vbmU', ObservedProperties::none(), self::binding(Purpose::SIGN_IN));
    }

    /**
     * A result keeps its factor and its recovery codes, none by default.
     *
     * @return void
     */
    public function testAResultKeepsItsFactorAndCodes(): void
    {
        $summary = new FactorSummary('factor-1', 'passkey', null, null, FactorStatus::CONFIRMED, false, null);
        $codes   = [new RevealedSecret('ABCDEFGHJKLM')];

        self::assertSame([], (new PasskeyAssociationResult($summary))->recoveryCodes);
        self::assertSame($summary, (new PasskeyAssociationResult($summary, $codes))->factor);
        self::assertSame($codes, (new PasskeyAssociationResult($summary, $codes))->recoveryCodes);
    }

    /**
     * A binding of a person on the web application for the purpose.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @return \SineMacula\Laravel\Mfa\Proofs\ProofBinding
     */
    private static function binding(Purpose $purpose): ProofBinding
    {
        return new ProofBinding('person', '1', 'web', 'sign-in-1', $purpose);
    }
}
