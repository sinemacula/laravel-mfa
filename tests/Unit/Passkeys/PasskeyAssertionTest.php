<?php

declare(strict_types = 1);

namespace Tests\Unit\Passkeys;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Assurance\ObservedProperties;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyAssertion;

/**
 * Unit tests for `PasskeyAssertion`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PasskeyAssertion::class)]
final class PasskeyAssertionTest extends TestCase
{
    /**
     * The assertion holds the credential and what it observed.
     *
     * @return void
     */
    public function testHoldsTheCredentialAndWhatItObserved(): void
    {
        $properties = new ObservedProperties(userPresence: true, userVerification: true);

        $assertion = new PasskeyAssertion('credential-1', $properties);

        self::assertSame('credential-1', $assertion->credentialId);
        self::assertSame($properties, $assertion->properties);
    }

    /**
     * A blank credential id is refused.
     *
     * @return void
     */
    public function testRefusesABlankCredentialId(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The credential id of a passkey assertion must not be blank.');

        new PasskeyAssertion(' ', ObservedProperties::none());
    }
}
