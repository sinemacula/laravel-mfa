<?php

declare(strict_types = 1);

namespace Tests\Unit\Events;

use Carbon\CarbonImmutable;
use Illuminate\Foundation\Testing\RefreshDatabase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Contracts\MfaEvent;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Events\Actor;
use SineMacula\Laravel\Mfa\Events\BootstrapEnrollmentCompleted;
use SineMacula\Laravel\Mfa\Events\CodeSent;
use SineMacula\Laravel\Mfa\Events\ContextEvent;
use SineMacula\Laravel\Mfa\Events\EnrollmentAbandoned;
use SineMacula\Laravel\Mfa\Events\EnrollmentEvent;
use SineMacula\Laravel\Mfa\Events\EnrollmentExpired;
use SineMacula\Laravel\Mfa\Events\EnrollmentStarted;
use SineMacula\Laravel\Mfa\Events\EventContext;
use SineMacula\Laravel\Mfa\Events\FactorConfirmed;
use SineMacula\Laravel\Mfa\Events\FactorDisabled;
use SineMacula\Laravel\Mfa\Events\FactorRemoved;
use SineMacula\Laravel\Mfa\Events\FactorRenamed;
use SineMacula\Laravel\Mfa\Events\FactorsReset;
use SineMacula\Laravel\Mfa\Events\LockoutApplied;
use SineMacula\Laravel\Mfa\Events\LockoutLifted;
use SineMacula\Laravel\Mfa\Events\PasskeyAssociated;
use SineMacula\Laravel\Mfa\Events\PreferredFactorChanged;
use SineMacula\Laravel\Mfa\Events\RecoveryCodeRedemptionEvent;
use SineMacula\Laravel\Mfa\Events\RecoveryCodesGenerated;
use SineMacula\Laravel\Mfa\Events\RecoveryCodesLow;
use SineMacula\Laravel\Mfa\Events\RecoveryCodesRemoved;
use SineMacula\Laravel\Mfa\Events\RecoveryCodeUsed;
use SineMacula\Laravel\Mfa\Events\VerificationFailed;
use SineMacula\Laravel\Mfa\Events\VerificationPassed;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;

/**
 * The event catalogue: every event a listener can take, each carrying its
 * context and payload, and none carrying a secret, a code, a provisioning URI
 * or a full destination, whether it is serialised for a queue or encoded as
 * JSON.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ContextEvent::class)]
#[CoversClass(EnrollmentEvent::class)]
#[CoversClass(EnrollmentStarted::class)]
#[CoversClass(FactorConfirmed::class)]
#[CoversClass(EnrollmentAbandoned::class)]
#[CoversClass(EnrollmentExpired::class)]
#[CoversClass(BootstrapEnrollmentCompleted::class)]
#[CoversClass(PasskeyAssociated::class)]
#[CoversClass(FactorRenamed::class)]
#[CoversClass(PreferredFactorChanged::class)]
#[CoversClass(FactorRemoved::class)]
#[CoversClass(FactorDisabled::class)]
#[CoversClass(FactorsReset::class)]
#[CoversClass(LockoutApplied::class)]
#[CoversClass(LockoutLifted::class)]
#[CoversClass(CodeSent::class)]
#[CoversClass(VerificationPassed::class)]
#[CoversClass(VerificationFailed::class)]
#[CoversClass(RecoveryCodeRedemptionEvent::class)]
#[CoversClass(RecoveryCodesGenerated::class)]
#[CoversClass(RecoveryCodeUsed::class)]
#[CoversClass(RecoveryCodesLow::class)]
#[CoversClass(RecoveryCodesRemoved::class)]
final class EventCatalogueTest extends TestCase
{
    use RefreshDatabase;

    /** @var string The TOTP secret stored on the factor. */
    private const string SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';

    /** @var string The code delivered for the factor. */
    private const string CODE = '493817';

    /** @var string The factor's full destination. */
    private const string DESTINATION = 'alice.liddell@example.com';

    /** @var string The credential the factor is associated with. */
    private const string CREDENTIAL = 'credential-reference-7f3a';

    /** @var array<string, int|string|null> The context every event is built with. */
    private const array CONTEXT = [
        'identity_type'  => TestUser::class,
        'identity_id'    => '1',
        'principal_type' => null,
        'principal_id'   => null,
        'tenant_id'      => null,
        'application'    => 'web',
        'session_id'     => null,
        'ip'             => '203.0.113.9',
        'user_agent'     => 'Mozilla/5.0',
    ];

    /**
     * Every event, built from a factor that holds a secret, a delivered code, a
     * credential reference and a full destination, with what it is for.
     *
     * @return iterable<string, array{\Closure(\SineMacula\Laravel\Mfa\Factors\FactorSummary): \SineMacula\Laravel\Mfa\Contracts\MfaEvent, ?\SineMacula\Laravel\Mfa\Enums\Purpose}>
     */
    public static function events(): iterable
    {
        $actor   = new Actor(TestUser::class, '2');
        $context = self::CONTEXT;

        yield 'EnrollmentStarted' => [static fn (FactorSummary $factor): MfaEvent => new EnrollmentStarted($context, $factor), Purpose::ENROLLMENT];
        yield 'FactorConfirmed' => [static fn (FactorSummary $factor): MfaEvent => new FactorConfirmed($context, $factor), Purpose::ENROLLMENT];
        yield 'EnrollmentAbandoned' => [static fn (FactorSummary $factor): MfaEvent => new EnrollmentAbandoned($context, $factor), Purpose::ENROLLMENT];
        yield 'EnrollmentExpired' => [static fn (FactorSummary $factor): MfaEvent => new EnrollmentExpired($context, $factor), Purpose::ENROLLMENT];
        yield 'BootstrapEnrollmentCompleted' => [static fn (FactorSummary $factor): MfaEvent => new BootstrapEnrollmentCompleted($context, $factor), Purpose::ENROLLMENT];
        yield 'PasskeyAssociated' => [static fn (FactorSummary $factor): MfaEvent => new PasskeyAssociated($context, $factor), Purpose::ENROLLMENT];
        yield 'FactorRenamed' => [static fn (FactorSummary $factor): MfaEvent => new FactorRenamed($context, $factor, 'Old label'), null];
        yield 'PreferredFactorChanged' => [static fn (FactorSummary $factor): MfaEvent => new PreferredFactorChanged($context, $factor, $factor), null];
        yield 'FactorRemoved' => [static fn (FactorSummary $factor): MfaEvent => new FactorRemoved($context, $factor, $actor), null];
        yield 'FactorDisabled' => [static fn (FactorSummary $factor): MfaEvent => new FactorDisabled($context, $factor, Purpose::SIGN_IN), Purpose::SIGN_IN];
        yield 'FactorsReset' => [static fn (): MfaEvent => new FactorsReset($context, $actor, 'Lost phone', false), null];
        yield 'LockoutApplied' => [
            static fn (FactorSummary $factor): MfaEvent => new LockoutApplied($context, $factor, CarbonImmutable::now()->addMinutes(15), Purpose::STEP_UP),
            Purpose::STEP_UP,
        ];
        yield 'LockoutLifted' => [static fn (FactorSummary $factor): MfaEvent => new LockoutLifted($context, $factor, $actor), null];
        yield 'CodeSent' => [static fn (FactorSummary $factor): MfaEvent => new CodeSent($context, $factor, Purpose::SIGN_IN, 'challenge-1'), Purpose::SIGN_IN];
        yield 'VerificationPassed' => [
            static fn (FactorSummary $factor): MfaEvent => new VerificationPassed($context, $factor, 'email', Purpose::STEP_UP, 'challenge-1'),
            Purpose::STEP_UP,
        ];
        yield 'VerificationFailed' => [
            static fn (FactorSummary $factor): MfaEvent => new VerificationFailed($context, $factor, 'email', Purpose::SIGN_IN, FailureReason::INVALID_CODE, 'challenge-1'),
            Purpose::SIGN_IN,
        ];
        yield 'RecoveryCodesGenerated' => [static fn (): MfaEvent => new RecoveryCodesGenerated($context, 10, 3, $actor), null];
        yield 'RecoveryCodeUsed' => [static fn (): MfaEvent => new RecoveryCodeUsed($context, 9, Purpose::STEP_UP), Purpose::STEP_UP];
        yield 'RecoveryCodesLow' => [static fn (): MfaEvent => new RecoveryCodesLow($context, 2, Purpose::SIGN_IN), Purpose::SIGN_IN];
        yield 'RecoveryCodesRemoved' => [static fn (): MfaEvent => new RecoveryCodesRemoved($context, $actor), null];
    }

    /**
     * No event carries the factor's secret, its delivered code, a provisioning
     * URI, its credential reference or its full destination, serialised for a
     * queue or encoded as JSON; each still carries its context.
     *
     * @param  \Closure(\SineMacula\Laravel\Mfa\Factors\FactorSummary): \SineMacula\Laravel\Mfa\Contracts\MfaEvent  $build
     * @param  ?\SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @return void
     */
    #[DataProvider('events')]
    public function testNoEventCarriesASecretACodeAUriOrAFullDestination(\Closure $build, ?Purpose $purpose): void
    {
        $event = $build(FactorSummary::fromFactor($this->sensitiveFactor()));

        $serialized = serialize($event);
        $encoded    = (string) json_encode($event);

        foreach ([$serialized, $encoded] as $payload) {
            self::assertStringNotContainsString(self::SECRET, $payload);
            self::assertStringNotContainsString(self::CODE, $payload);
            self::assertStringNotContainsString(self::DESTINATION, $payload);
            self::assertStringNotContainsString(self::CREDENTIAL, $payload);
            self::assertStringNotContainsString('otpauth://', $payload);
        }

        self::assertStringNotContainsString(Factor::class, $serialized);
        self::assertSame(self::CONTEXT, $event->context());
        self::assertSame($purpose, $event->purpose());
        self::assertEquals($event, unserialize($serialized));
    }

    /**
     * Every event is one a single listener on the contract takes, with the
     * context it was built with.
     *
     * @param  \Closure(\SineMacula\Laravel\Mfa\Factors\FactorSummary): \SineMacula\Laravel\Mfa\Contracts\MfaEvent  $build
     * @param  ?\SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @return void
     */
    #[DataProvider('events')]
    public function testEveryEventCarriesItsContext(\Closure $build, ?Purpose $purpose): void
    {
        $event = $build(FactorSummary::fromFactor($this->sensitiveFactor()));

        self::assertInstanceOf(ContextEvent::class, $event);
        self::assertSame(EventContext::KEYS, array_keys($event->context()));
    }

    /**
     * Every event says what it was for: the purpose of the attempt, code or
     * proof behind it where that varies, enrolment for an enrolment's events,
     * and nothing for a change made outside any verification.
     *
     * @param  \Closure(\SineMacula\Laravel\Mfa\Factors\FactorSummary): \SineMacula\Laravel\Mfa\Contracts\MfaEvent  $build
     * @param  ?\SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @return void
     */
    #[DataProvider('events')]
    public function testEveryEventSaysWhatItWasFor(\Closure $build, ?Purpose $purpose): void
    {
        $event = $build(FactorSummary::fromFactor($this->sensitiveFactor()));

        self::assertSame($purpose, $event->purpose());
    }

    /**
     * The events' payloads, by name, so a renamed field fails.
     *
     * @return void
     */
    public function testThePayloadsAreTheStableFields(): void
    {
        $factor = FactorSummary::fromFactor($this->sensitiveFactor());
        $actor  = new Actor(TestUser::class, '2');
        $until  = CarbonImmutable::parse('2026-11-01T12:00:00Z');

        $renamed = new FactorRenamed(self::CONTEXT, $factor, 'Old label');
        self::assertSame([$factor, 'Old label'], [$renamed->factor, $renamed->previousLabel]);

        $preferred = new PreferredFactorChanged(self::CONTEXT, $factor);
        self::assertSame([$factor, null], [$preferred->factor, $preferred->previous]);

        $removed = new FactorRemoved(self::CONTEXT, $factor);
        self::assertNull($removed->actor);

        $reset = new FactorsReset(self::CONTEXT, $actor);
        self::assertSame([$actor, null, true], [$reset->actor, $reset->reason, $reset->reenrollmentRequired]);

        $applied = new LockoutApplied(self::CONTEXT, null, $until, Purpose::SIGN_IN);
        self::assertSame([null, $until, Purpose::SIGN_IN], [$applied->factor, $applied->lockedUntil, $applied->purpose]);

        $lifted = new LockoutLifted(self::CONTEXT);
        self::assertSame([null, null], [$lifted->factor, $lifted->actor]);

        $sent = new CodeSent(self::CONTEXT, $factor, Purpose::SIGN_IN);
        self::assertSame([$factor, Purpose::SIGN_IN, null], [$sent->factor, $sent->purpose, $sent->challengeId]);

        $passed = new VerificationPassed(self::CONTEXT, null, 'recovery_code', Purpose::STEP_UP);
        self::assertSame([null, 'recovery_code', Purpose::STEP_UP, null], [$passed->factor, $passed->type, $passed->purpose, $passed->challengeId]);

        $failed = new VerificationFailed(self::CONTEXT, null, null, Purpose::SIGN_IN, FailureReason::NOT_FOUND);
        self::assertSame([null, null, Purpose::SIGN_IN, FailureReason::NOT_FOUND, null], [$failed->factor, $failed->type, $failed->purpose, $failed->reason, $failed->challengeId]);

        $generated = new RecoveryCodesGenerated(self::CONTEXT, 10, 3);
        self::assertSame([10, 3, null], [$generated->count, $generated->generation, $generated->actor]);

        $used = new RecoveryCodeUsed(self::CONTEXT, 9, Purpose::STEP_UP);
        self::assertSame([9, Purpose::STEP_UP], [$used->remaining, $used->purpose]);

        $low = new RecoveryCodesLow(self::CONTEXT, 2, Purpose::SIGN_IN);
        self::assertSame([2, Purpose::SIGN_IN], [$low->remaining, $low->purpose]);

        $disabled = new FactorDisabled(self::CONTEXT, $factor, Purpose::REAUTHENTICATE);
        self::assertSame([$factor, Purpose::REAUTHENTICATE], [$disabled->factor, $disabled->purpose]);
        self::assertNull((new RecoveryCodesRemoved(self::CONTEXT))->actor);
        self::assertSame($factor, (new FactorConfirmed(self::CONTEXT, $factor))->factor);
    }

    /**
     * A factor holding everything an event must not carry.
     *
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function sensitiveFactor(): Factor
    {
        $user = TestUser::query()->create(['email' => 'alice@example.test', 'mfa_enabled' => true]);

        return Factor::query()->create([
            'authenticatable_type' => $user->getMorphClass(),
            'authenticatable_id'   => (string) $user->id,
            'type'                 => 'email',
            'label'                => 'Work email',
            'destination'          => self::DESTINATION,
            'credential_reference' => self::CREDENTIAL,
            'secret'               => self::SECRET,
            'code'                 => self::CODE,
            'status'               => 'confirmed',
        ]);
    }
}
