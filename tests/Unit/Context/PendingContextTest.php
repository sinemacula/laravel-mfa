<?php

declare(strict_types = 1);

namespace Tests\Unit\Context;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Assurance\Channel;
use SineMacula\Laravel\Mfa\Assurance\ObservedProperties;
use SineMacula\Laravel\Mfa\Context\PendingContext;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use Tests\Fixtures\Identities\NonEloquentIdentity;
use Tests\Fixtures\Verification\Dumps;
use Tests\Unit\Concerns\BuildsProofs;

/**
 * Unit tests for `PendingContext`: what it holds, the actions it allows, and
 * the contradictions it refuses.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PendingContext::class)]
final class PendingContextTest extends TestCase
{
    use BuildsProofs;

    /**
     * The context holds its parts and allows exactly the listed actions.
     *
     * @return void
     */
    public function testHoldsItsPartsAndAllowsOnlyTheListedActions(): void
    {
        $identity    = new NonEloquentIdentity('42');
        $firstFactor = self::firstFactor();
        $requirement = Requirement::none()->withAdditionalVerification();

        $context = new PendingContext(
            $identity,
            'admin',
            'session-1',
            $firstFactor,
            $requirement,
            [PendingAction::LIST_FACTORS, PendingAction::VERIFY],
            CarbonImmutable::now()->addHour(),
        );

        self::assertSame($identity, $context->identity);
        self::assertSame('admin', $context->application);
        self::assertSame('session-1', $context->sessionId);
        self::assertSame($firstFactor, $context->firstFactor);
        self::assertSame($requirement, $context->requirement);
        self::assertSame([PendingAction::LIST_FACTORS, PendingAction::VERIFY], $context->actions);

        self::assertTrue($context->allows(PendingAction::LIST_FACTORS));
        self::assertTrue($context->allows(PendingAction::VERIFY));
        self::assertFalse($context->allows(PendingAction::SEND_CODE));
        self::assertFalse($context->allows(PendingAction::START_BOOTSTRAP_ENROLLMENT));
    }

    /**
     * A session's further proofs are held as they came, and it holds none
     * unless given.
     *
     * @return void
     */
    public function testHoldsItsFurtherProofs(): void
    {
        $further = self::proof(['binding' => self::binding(Purpose::SIGN_IN)]);

        self::assertSame([$further], self::context(['proofs' => [$further]])->proofs);
        self::assertSame([], self::context()->proofs);
    }

    /**
     * A context that allows nothing is valid, and allows nothing.
     *
     * @return void
     */
    public function testAllowsNothingWithoutActions(): void
    {
        $context = self::context();

        foreach (PendingAction::cases() as $action) {
            self::assertFalse($context->allows($action));
        }
    }

    /**
     * An identity with an integer key matches a binding of its string form.
     *
     * @return void
     */
    public function testMatchesAnIntegerKeyByItsStringForm(): void
    {
        $context = self::context(['identity' => new NonEloquentIdentity(42)]);

        self::assertSame('42', $context->firstFactor->binding->identityKey);
    }

    /**
     * Contradictory contexts and the message each is refused with.
     *
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function contradictions(): iterable
    {
        $bound = 'The first factor of a pending session must be bound to its identity, application and session.';

        yield 'blank application' => [['application' => ' '], 'The application of a pending session must not be blank.'];
        yield 'blank session id' => [['sessionId' => ' '], 'The session id of a pending session must not be blank.'];
        yield 'not a first factor' => [
            ['firstFactor' => self::proof(['binding' => self::binding(Purpose::STEP_UP)])],
            'The first factor of a pending session must be a proof of kind [first_factor].',
        ];
        yield 'another identity type' => [['firstFactor' => self::firstFactor(['identityType' => 'user'])], $bound];
        yield 'another identity key' => [['firstFactor' => self::firstFactor(['identityKey' => '43'])], $bound];
        yield 'another application' => [['firstFactor' => self::firstFactor(['application' => 'mobile'])], $bound];
        yield 'another session' => [['firstFactor' => self::firstFactor(['sessionId' => 'session-2'])], $bound];
        yield 'an unsupported key' => [['identity' => new NonEloquentIdentity((object) ['id' => 42])], $bound];
        $further = 'The further proofs of a pending session must be bound to its identity, application and session.';

        yield 'a further first factor' => [['proofs' => [self::firstFactor()]], 'The further proofs of a pending session must not hold a first factor.'];
        yield 'a further proof of another identity type' => [['proofs' => [self::proof(['binding' => self::binding(Purpose::STEP_UP, ['identityType' => 'user'])])]], $further];
        yield 'a further proof of another identity key' => [['proofs' => [self::proof(['binding' => self::binding(Purpose::STEP_UP, ['identityKey' => '43'])])]], $further];
        yield 'a further proof of another application' => [['proofs' => [self::proof(['binding' => self::binding(Purpose::STEP_UP, ['application' => 'mobile'])])]], $further];
        yield 'a further proof of another session' => [['proofs' => [self::proof(['binding' => self::binding(Purpose::STEP_UP, ['sessionId' => 'session-2'])])]], $further];
        yield 'actions not a list' => [['actions' => [1 => PendingAction::VERIFY]], 'The actions of a pending session must be a list.'];
        yield 'not a pending action' => [['actions' => ['mfa.verify']], 'The actions of a pending session must be ' . PendingAction::class . ' cases; got [string].'];
        yield 'an action named twice' => [
            ['actions' => [PendingAction::VERIFY, PendingAction::SEND_CODE, PendingAction::VERIFY]],
            'The pending action [mfa.verify] is named more than once.',
        ];
    }

    /**
     * A contradictory context is refused.
     *
     * @param  array<string, mixed>  $overrides
     * @param  string  $message
     * @return void
     */
    #[DataProvider('contradictions')]
    public function testRefusesAContradiction(array $overrides, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        self::context($overrides);
    }

    /**
     * The credential the caller presented is kept, read back through
     * `credential()`, and shown by no dump; without one it is `null`.
     *
     * @return void
     */
    public function testKeepsThePresentedCredentialOutOfEveryDump(): void
    {
        $pending = self::context(['credential' => 'pending-credential-7731']);

        self::assertSame('pending-credential-7731', $pending->credential());
        self::assertNull(self::context()->credential());

        foreach (Dumps::of($pending) as $way => $dump) {
            self::assertStringNotContainsString('pending-credential-7731', $dump, $way);
        }
    }

    /**
     * Build a pending context for the fixture identity, with any argument
     * overridden by name.
     *
     * @param  array<string, mixed>  $overrides
     * @return \SineMacula\Laravel\Mfa\Context\PendingContext
     */
    private static function context(array $overrides = []): PendingContext
    {
        /** @phpstan-ignore argument.type (the overrides are named arguments of the constructor) */
        return new PendingContext(...array_merge([
            'identity'    => new NonEloquentIdentity('42'),
            'application' => 'admin',
            'sessionId'   => 'session-1',
            'firstFactor' => self::firstFactor(),
            'requirement' => Requirement::none(),
            'actions'     => [],
            'expiresAt'   => CarbonImmutable::now()->addMinutes(10),
        ], $overrides));
    }

    /**
     * A password first factor bound to the fixture identity's sign-in, with any
     * part of the binding overridden by name.
     *
     * @param  array<string, string>  $binding
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     */
    private static function firstFactor(array $binding = []): Proof
    {
        return new Proof(
            kind      : ProofKind::FIRST_FACTOR,
            method    : 'password',
            channel   : new Channel(ChannelKind::PASSWORD),
            reference : null,
            properties: ObservedProperties::none(),
            provedAt  : CarbonImmutable::parse('2026-11-01T09:00:00+00:00'),
            binding   : self::binding(Purpose::SIGN_IN, $binding),
            generation: 0,
        );
    }

    /**
     * A binding to the fixture identity's session, with any part overridden by
     * name.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @param  array<string, string>  $overrides
     * @return \SineMacula\Laravel\Mfa\Proofs\ProofBinding
     */
    private static function binding(Purpose $purpose, array $overrides = []): ProofBinding
    {
        return new ProofBinding(
            identityType: $overrides['identityType'] ?? NonEloquentIdentity::class,
            identityKey : $overrides['identityKey']  ?? '42',
            application : $overrides['application']  ?? 'admin',
            sessionId   : $overrides['sessionId']    ?? 'session-1',
            purpose     : $purpose,
        );
    }
}
