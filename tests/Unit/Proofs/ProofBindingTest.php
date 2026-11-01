<?php

declare(strict_types = 1);

namespace Tests\Unit\Proofs;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;

/**
 * Unit tests for the `ProofBinding` value: construction, validation and
 * serialisation.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ProofBinding::class)]
final class ProofBindingTest extends TestCase
{
    /**
     * A binding keeps the identity, application, session and purpose.
     *
     * @return void
     */
    public function testABindingKeepsWhatItBindsTo(): void
    {
        $binding = new ProofBinding('user', '42', 'admin', 'session-1', Purpose::STEP_UP);

        self::assertSame('user', $binding->identityType);
        self::assertSame('42', $binding->identityKey);
        self::assertSame('admin', $binding->application);
        self::assertSame('session-1', $binding->sessionId);
        self::assertSame(Purpose::STEP_UP, $binding->purpose);
    }

    /**
     * Bindings with a blank part.
     *
     * @return iterable<string, array{string, string, string, string, string}>
     */
    public static function provideBlankParts(): iterable
    {
        yield 'identity type' => ['', '42', 'admin', 'session-1', 'The identity type of a proof binding must not be blank.'];
        yield 'identity key' => ['user', ' ', 'admin', 'session-1', 'The identity key of a proof binding must not be blank.'];
        yield 'application' => ['user', '42', "\n", 'session-1', 'The application of a proof binding must not be blank.'];
        yield 'session id' => ['user', '42', 'admin', '', 'The session id of a proof binding must not be blank.'];
    }

    /**
     * Every part of a binding is required.
     *
     * @param  string  $identityType
     * @param  string  $identityKey
     * @param  string  $application
     * @param  string  $sessionId
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideBlankParts')]
    public function testABlankPartIsRefused(string $identityType, string $identityKey, string $application, string $sessionId, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        new ProofBinding($identityType, $identityKey, $application, $sessionId, Purpose::SIGN_IN);
    }

    /**
     * The serialised form uses snake_case keys and the purpose's value.
     *
     * @return void
     */
    public function testTheSerializedForm(): void
    {
        $binding = new ProofBinding('user', '42', 'admin', 'session-1', Purpose::ENROLLMENT);

        $expected = [
            'identity_type' => 'user',
            'identity_key'  => '42',
            'application'   => 'admin',
            'session_id'    => 'session-1',
            'purpose'       => 'enrollment',
        ];

        self::assertSame($expected, $binding->toArray());
        self::assertSame($expected, $binding->jsonSerialize());
    }

    /**
     * A binding read back from its serialised form equals the original.
     *
     * @return void
     */
    public function testABindingRoundTrips(): void
    {
        $binding = new ProofBinding('user', '42', 'admin', 'session-1', Purpose::REAUTHENTICATE);

        self::assertEquals($binding, ProofBinding::fromArray($binding->toArray()));
    }

    /**
     * Serialised forms that are not a binding.
     *
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function provideMalformedBindings(): iterable
    {
        $valid = ['identity_type' => 'user', 'identity_key' => '42', 'application' => 'admin', 'session_id' => 'session-1', 'purpose' => 'sign_in'];

        yield 'no identity type' => [array_diff_key($valid, ['identity_type' => true]), 'The [identity_type] field of a serialised proof binding must be a string.'];
        yield 'an identity key that is not a string' => [['identity_key' => 42] + $valid, 'The [identity_key] field of a serialised proof binding must be a string.'];
        yield 'no application' => [array_diff_key($valid, ['application' => true]), 'The [application] field of a serialised proof binding must be a string.'];
        yield 'no session id' => [array_diff_key($valid, ['session_id' => true]), 'The [session_id] field of a serialised proof binding must be a string.'];
        yield 'an unknown purpose' => [['purpose' => 'sign_up'] + $valid, 'The [purpose] field of a serialised proof binding is not a known value.'];
        yield 'a blank session id' => [['session_id' => ''] + $valid, 'The session id of a proof binding must not be blank.'];
        yield 'an unknown field' => [['tenant' => 'acme'] + $valid, 'The [tenant] field of a serialised proof binding is not a known field.'];
    }

    /**
     * A serialised form that is not a binding is refused.
     *
     * @param  array<string, mixed>  $data
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideMalformedBindings')]
    public function testAMalformedBindingIsRefused(array $data, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        ProofBinding::fromArray($data);
    }
}
