<?php

declare(strict_types = 1);

namespace Tests\Unit\Proofs;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Assurance\Channel;
use SineMacula\Laravel\Mfa\Assurance\ObservedProperties;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\KeyProtection;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use Tests\Unit\Concerns\BuildsProofs;

/**
 * Unit tests for the `Proof` value: construction, the rules between its kind,
 * channel, reference and purpose, and serialisation.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Proof::class)]
final class ProofTest extends TestCase
{
    use BuildsProofs;

    /**
     * A proof keeps everything it was made with.
     *
     * @return void
     */
    public function testAProofKeepsWhatItWasMadeWith(): void
    {
        $channel    = new Channel(ChannelKind::PASSKEY, 'credential-1');
        $properties = new ObservedProperties(userPresence: true, userVerification: true);
        $provedAt   = CarbonImmutable::parse('2026-11-01T10:00:00+00:00');
        $binding    = new ProofBinding('user', '42', 'admin', 'session-1', Purpose::SIGN_IN);

        $proof = new Proof(ProofKind::FIRST_FACTOR, 'passkey', $channel, 'credential-1', $properties, $provedAt, $binding, 0, 'challenge-1');

        self::assertSame(ProofKind::FIRST_FACTOR, $proof->kind);
        self::assertSame('passkey', $proof->method);
        self::assertSame($channel, $proof->channel);
        self::assertSame('credential-1', $proof->reference);
        self::assertSame($properties, $proof->properties);
        self::assertSame($provedAt, $proof->provedAt);
        self::assertSame($binding, $proof->binding);
        self::assertSame(0, $proof->generation);
        self::assertSame('challenge-1', $proof->challengeId);
    }

    /**
     * A first factor needs no reference or challenge, and a recovery code no
     * channel.
     *
     * @return void
     */
    public function testTheOptionalParts(): void
    {
        $password = self::proof([
            'kind'      => ProofKind::FIRST_FACTOR,
            'method'    => 'password',
            'channel'   => new Channel(ChannelKind::PASSWORD),
            'reference' => null,
            'binding'   => new ProofBinding('user', '42', 'admin', 'session-1', Purpose::SIGN_IN),
        ]);

        $recovery = self::proof(['kind' => ProofKind::RECOVERY_CODE, 'method' => 'recovery_code', 'channel' => null, 'reference' => null]);

        self::assertNull($password->reference);
        self::assertNull($password->challengeId);
        self::assertNull($recovery->channel);
        self::assertNull($recovery->reference);
    }

    /**
     * Proofs whose parts contradict each other or are blank.
     *
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function provideInvalidProofs(): iterable
    {
        $signIn     = new ProofBinding('user', '42', 'admin', 'session-1', Purpose::SIGN_IN);
        $enrollment = new ProofBinding('user', '42', 'admin', 'session-1', Purpose::ENROLLMENT);

        yield 'a blank method' => [['method' => ' '], 'The method of a proof must not be blank.'];
        yield 'a first factor without a channel' => [
            ['kind' => ProofKind::FIRST_FACTOR, 'channel' => null, 'binding' => $signIn],
            'A proof of kind [first_factor] needs a channel.',
        ];
        yield 'an additional factor without a channel' => [['channel' => null], 'A proof of kind [additional_factor] needs a channel.'];
        yield 'a recovery code with a channel' => [['kind' => ProofKind::RECOVERY_CODE], 'A proof of kind [recovery_code] has no channel.'];
        yield 'an additional factor on an unknown channel' => [
            ['channel' => Channel::unknown()],
            'An additional factor proof cannot travel on a channel of kind [unknown].',
        ];
        yield 'an additional factor on a password channel' => [
            ['channel' => new Channel(ChannelKind::PASSWORD)],
            'An additional factor proof cannot travel on a channel of kind [password].',
        ];
        yield 'a blank reference' => [['reference' => ''], 'The factor or credential reference of a proof must not be blank.'];
        yield 'a reference of spaces' => [['reference' => ' '], 'The factor or credential reference of a proof must not be blank.'];
        yield 'an additional factor without a reference' => [['reference' => null], 'An additional factor proof needs the reference of the factor it was made with.'];
        yield 'a first factor on a step-up' => [['kind' => ProofKind::FIRST_FACTOR], 'A proof of kind [first_factor] carries the [sign_in] purpose, not [step_up].'];
        yield 'a reauthentication at sign-in' => [
            ['kind' => ProofKind::FIRST_FACTOR_REAUTHENTICATION, 'binding' => $signIn],
            'A proof of kind [first_factor_reauthentication] carries the [reauthenticate] purpose, not [sign_in].',
        ];
        yield 'a recovery code confirming an enrolment' => [
            ['kind' => ProofKind::RECOVERY_CODE, 'channel' => null, 'binding' => $enrollment],
            'A recovery code proof cannot confirm an enrolment.',
        ];
        yield 'a negative generation' => [['generation' => -1], 'The verification generation of a proof must not be negative.'];
        yield 'a blank challenge id' => [['challengeId' => ''], 'The challenge id of a proof must not be blank.'];
        yield 'a challenge id of spaces' => [['challengeId' => '  '], 'The challenge id of a proof must not be blank.'];
    }

    /**
     * A proof whose parts contradict each other, or that has a blank part, is
     * refused.
     *
     * @param  array<string, mixed>  $overrides
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideInvalidProofs')]
    public function testAnInvalidProofIsRefused(array $overrides, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        self::proof($overrides);
    }

    /**
     * A reauthentication with the first factor carries the reauthenticate
     * purpose, an additional factor may serve any purpose, and a recovery code
     * any but an enrolment.
     *
     * @return void
     */
    public function testThePurposesEachKindAccepts(): void
    {
        $reauthenticate = new ProofBinding('user', '42', 'admin', 'session-1', Purpose::REAUTHENTICATE);

        $proof = self::proof(['kind' => ProofKind::FIRST_FACTOR_REAUTHENTICATION, 'reference' => null, 'binding' => $reauthenticate]);

        self::assertSame(Purpose::REAUTHENTICATE, $proof->binding->purpose);

        foreach (Purpose::cases() as $purpose) {
            $binding = new ProofBinding('user', '42', 'admin', 'session-1', $purpose);

            self::assertSame($purpose, self::proof(['binding' => $binding])->binding->purpose);
        }

        foreach ([Purpose::SIGN_IN, Purpose::REAUTHENTICATE, Purpose::STEP_UP] as $purpose) {
            $binding = new ProofBinding('user', '42', 'admin', 'session-1', $purpose);

            self::assertSame($purpose, self::proof(['kind' => ProofKind::RECOVERY_CODE, 'channel' => null, 'binding' => $binding])->binding->purpose);
        }
    }

    /**
     * A first factor or a reauthentication with it may travel on an unknown
     * channel, which only an additional factor is refused.
     *
     * @return void
     */
    public function testAFirstFactorMayHaveAnUnknownChannel(): void
    {
        $signIn         = new ProofBinding('user', '42', 'admin', 'session-1', Purpose::SIGN_IN);
        $reauthenticate = new ProofBinding('user', '42', 'admin', 'session-1', Purpose::REAUTHENTICATE);

        $first = self::proof(['kind' => ProofKind::FIRST_FACTOR, 'channel' => Channel::unknown(), 'reference' => null, 'binding' => $signIn]);
        $again = self::proof(['kind' => ProofKind::FIRST_FACTOR_REAUTHENTICATION, 'channel' => Channel::unknown(), 'reference' => null, 'binding' => $reauthenticate]);

        self::assertSame(ChannelKind::UNKNOWN, $first->channel?->kind);
        self::assertSame(ChannelKind::UNKNOWN, $again->channel?->kind);
    }

    /**
     * The serialised form uses snake_case keys, nests the channel, properties
     * and binding, and keeps the time to the microsecond with its offset.
     *
     * @return void
     */
    public function testTheSerializedForm(): void
    {
        $proof = self::proof([
            'properties'  => new ObservedProperties(keyProtection: KeyProtection::HARDWARE),
            'challengeId' => 'challenge-9',
        ]);

        $expected = [
            'kind'       => 'additional_factor',
            'method'     => 'totp',
            'channel'    => ['kind' => 'authenticator_app', 'reference' => 'factor-1'],
            'reference'  => 'factor-1',
            'properties' => [
                'user_presence'       => null,
                'user_verification'   => null,
                'backup_eligibility'  => null,
                'backup_state'        => null,
                'phishing_resistance' => null,
                'key_protection'      => 'hardware',
            ],
            'proved_at' => '2026-11-01T09:30:15.123456+00:00',
            'binding'   => [
                'identity_type' => 'user',
                'identity_key'  => '42',
                'application'   => 'admin',
                'session_id'    => 'session-1',
                'purpose'       => 'step_up',
            ],
            'generation'   => 3,
            'challenge_id' => 'challenge-9',
        ];

        self::assertSame($expected, $proof->toArray());
        self::assertSame($expected, $proof->jsonSerialize());
        self::assertNull(self::proof(['kind' => ProofKind::RECOVERY_CODE, 'channel' => null])->toArray()['channel']);
    }

    /**
     * A proof read back from its serialised form, or from its JSON, equals the
     * original, to the microsecond.
     *
     * @return void
     */
    public function testAProofRoundTrips(): void
    {
        $proof    = self::proof(['challengeId' => 'challenge-9', 'provedAt' => CarbonImmutable::parse('2026-11-01T11:30:15.000001+01:00')]);
        $recovery = self::proof(['kind' => ProofKind::RECOVERY_CODE, 'channel' => null, 'reference' => null]);

        /** @var array<string, mixed> $decoded */
        $decoded = json_decode((string) json_encode($proof), true);

        self::assertEquals($proof, Proof::fromArray($proof->toArray()));
        self::assertEquals($proof, Proof::fromArray($decoded));
        self::assertEquals($recovery, Proof::fromArray($recovery->toArray()));
        self::assertSame('+01:00', Proof::fromArray($decoded)->provedAt->format('P'));
    }

    /**
     * Serialised forms that are not a proof.
     *
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function provideMalformedProofs(): iterable
    {
        $valid   = self::proof()->toArray();
        $binding = self::proof()->binding->toArray();

        yield 'an unknown kind' => [['kind' => 'second_factor'] + $valid, 'The [kind] field of a serialised proof is not a known value.'];
        yield 'an unknown field' => [['challengeId' => 'challenge-9'] + $valid, 'The [challengeId] field of a serialised proof is not a known field.'];
        yield 'an unknown field in the binding' => [
            ['binding' => ['session' => 'session-2'] + $binding] + $valid,
            'The [session] field of a serialised proof binding is not a known field.',
        ];
        yield 'no method' => [array_diff_key($valid, ['method' => true]), 'The [method] field of a serialised proof must be a string.'];
        yield 'a channel that is not an array' => [['channel' => 'sms'] + $valid, 'The [channel] field of a serialised proof must be an array or null.'];
        yield 'a reference that is not a string' => [['reference' => 1] + $valid, 'The [reference] field of a serialised proof must be a string or null.'];
        yield 'no properties' => [array_diff_key($valid, ['properties' => true]), 'The [properties] field of a serialised proof must be an array.'];
        yield 'a time that is not a string' => [['proved_at' => 1762000000] + $valid, 'The [proved_at] field of a serialised proof must be a string.'];
        yield 'a time without microseconds' => [
            ['proved_at' => '2026-11-01T09:30:15+00:00'] + $valid,
            'The [proved_at] field of a serialised proof is not a time in the serialised format.',
        ];
        yield 'a time that overflows' => [
            ['proved_at' => '2026-13-01T09:30:15.000000+00:00'] + $valid,
            'The [proved_at] field of a serialised proof is not a time in the serialised format.',
        ];
        yield 'no binding' => [array_diff_key($valid, ['binding' => true]), 'The [binding] field of a serialised proof must be an array.'];
        yield 'a generation that is not an integer' => [['generation' => '3'] + $valid, 'The [generation] field of a serialised proof must be an integer.'];
        yield 'a challenge id that is not a string' => [['challenge_id' => 9] + $valid, 'The [challenge_id] field of a serialised proof must be a string or null.'];
        yield 'a malformed channel' => [['channel' => ['kind' => 'fax']] + $valid, 'The [kind] field of a serialised channel is not a known value.'];
        yield 'a contradiction' => [['channel' => null] + $valid, 'A proof of kind [additional_factor] needs a channel.'];
        yield 'a recovery code confirming an enrolment' => [
            ['kind' => 'recovery_code', 'channel' => null, 'binding' => ['purpose' => 'enrollment'] + $binding] + $valid,
            'A recovery code proof cannot confirm an enrolment.',
        ];
    }

    /**
     * A serialised form that is not a proof is refused.
     *
     * @param  array<string, mixed>  $data
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideMalformedProofs')]
    public function testAMalformedProofIsRefused(array $data, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        Proof::fromArray($data);
    }
}
