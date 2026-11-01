<?php

declare(strict_types = 1);

namespace Tests\Unit\Assurance;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Assurance\ObservedProperties;
use SineMacula\Laravel\Mfa\Enums\KeyProtection;

/**
 * Unit tests for the `ObservedProperties` value: nothing is assumed, the
 * WebAuthn backup flags stay consistent, and the value serialises.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ObservedProperties::class)]
final class ObservedPropertiesTest extends TestCase
{
    /**
     * Nothing is observed unless it is given: no property defaults to true.
     *
     * @return void
     */
    public function testNothingIsObservedByDefault(): void
    {
        foreach ([new ObservedProperties, ObservedProperties::none()] as $properties) {
            self::assertNull($properties->userPresence);
            self::assertNull($properties->userVerification);
            self::assertNull($properties->backupEligibility);
            self::assertNull($properties->backupState);
            self::assertNull($properties->phishingResistance);
            self::assertNull($properties->keyProtection);
        }
    }

    /**
     * The properties keep what was observed, false included.
     *
     * @return void
     */
    public function testThePropertiesKeepWhatWasObserved(): void
    {
        $properties = new ObservedProperties(
            userPresence: true,
            userVerification: false,
            backupEligibility: true,
            backupState: false,
            phishingResistance: true,
            keyProtection: KeyProtection::HARDWARE,
        );

        self::assertTrue($properties->userPresence);
        self::assertFalse($properties->userVerification);
        self::assertTrue($properties->backupEligibility);
        self::assertFalse($properties->backupState);
        self::assertTrue($properties->phishingResistance);
        self::assertSame(KeyProtection::HARDWARE, $properties->keyProtection);
    }

    /**
     * A credential seen backed up while seen as not eligible for backup is a
     * contradiction WebAuthn rules out.
     *
     * @return void
     */
    public function testABackedUpCredentialThatCannotBeBackedUpIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A credential cannot be observed backed up when it was observed as not eligible for backup.');

        new ObservedProperties(backupEligibility: false, backupState: true);
    }

    /**
     * Backup combinations that are consistent.
     *
     * @return iterable<string, array{?bool, ?bool}>
     */
    public static function provideConsistentBackupFlags(): iterable
    {
        yield 'neither observed' => [null, null];
        yield 'backed up with eligibility not observed' => [null, true];
        yield 'eligible and backed up' => [true, true];
        yield 'eligible and not backed up' => [true, false];
        yield 'neither eligible nor backed up' => [false, false];
        yield 'not eligible with state not observed' => [false, null];
    }

    /**
     * Every other combination of the backup flags is accepted.
     *
     * @param  ?bool  $eligibility
     * @param  ?bool  $state
     * @return void
     */
    #[DataProvider('provideConsistentBackupFlags')]
    public function testConsistentBackupFlagsAreAccepted(?bool $eligibility, ?bool $state): void
    {
        $properties = new ObservedProperties(backupEligibility: $eligibility, backupState: $state);

        self::assertSame($eligibility, $properties->backupEligibility);
        self::assertSame($state, $properties->backupState);
    }

    /**
     * The serialised form uses snake_case keys, with null for what was not
     * observed.
     *
     * @return void
     */
    public function testTheSerializedForm(): void
    {
        $properties = new ObservedProperties(userPresence: true, keyProtection: KeyProtection::SOFTWARE);

        $expected = [
            'user_presence'       => true,
            'user_verification'   => null,
            'backup_eligibility'  => null,
            'backup_state'        => null,
            'phishing_resistance' => null,
            'key_protection'      => 'software',
        ];

        self::assertSame($expected, $properties->toArray());
        self::assertSame($expected, $properties->jsonSerialize());
    }

    /**
     * The properties read back from their serialised form equal the originals,
     * and a missing key reads as not observed.
     *
     * @return void
     */
    public function testThePropertiesRoundTrip(): void
    {
        $properties = new ObservedProperties(true, true, true, true, true, KeyProtection::HARDWARE);

        self::assertEquals($properties, ObservedProperties::fromArray($properties->toArray()));
        self::assertEquals(ObservedProperties::none(), ObservedProperties::fromArray([]));
    }

    /**
     * Serialised forms that are not observed properties.
     *
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function provideMalformedProperties(): iterable
    {
        yield 'a presence that is not a boolean' => [['user_presence' => 'yes'], 'The [user_presence] field of serialised observed properties must be a boolean or null.'];
        yield 'a verification that is not a boolean' => [['user_verification' => 1], 'The [user_verification] field of serialised observed properties must be a boolean or null.'];
        yield 'an eligibility that is not a boolean' => [
            ['backup_eligibility' => 0],
            'The [backup_eligibility] field of serialised observed properties must be a boolean or null.',
        ];
        yield 'a state that is not a boolean' => [['backup_state' => 'no'], 'The [backup_state] field of serialised observed properties must be a boolean or null.'];
        yield 'a resistance that is not a boolean' => [
            ['phishing_resistance' => []],
            'The [phishing_resistance] field of serialised observed properties must be a boolean or null.',
        ];
        yield 'an unknown field' => [['user_presence' => true, 'uv' => true], 'The [uv] field of serialised observed properties is not a known field.'];
        yield 'an unknown key protection' => [['key_protection' => 'quantum'], 'The [key_protection] field of serialised observed properties is not a known value.'];
        yield 'inconsistent backup flags' => [
            ['backup_eligibility' => false, 'backup_state' => true],
            'A credential cannot be observed backed up when it was observed as not eligible for backup.',
        ];
    }

    /**
     * A serialised form that is not observed properties is refused.
     *
     * @param  array<string, mixed>  $data
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideMalformedProperties')]
    public function testMalformedPropertiesAreRefused(array $data, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        ObservedProperties::fromArray($data);
    }
}
