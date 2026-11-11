<?php

declare(strict_types = 1);

namespace Tests\Feature\Passkeys;

use Carbon\CarbonImmutable;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Assurance\ObservedProperties;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Context\PendingContext;
use SineMacula\Laravel\Mfa\Contracts\FreshnessGate;
use SineMacula\Laravel\Mfa\Contracts\IdentityRequirement;
use SineMacula\Laravel\Mfa\Contracts\PendingCompletion;
use SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Contracts\Reauthenticator;
use SineMacula\Laravel\Mfa\Contracts\SessionRevoker;
use SineMacula\Laravel\Mfa\Contracts\SessionTransition;
use SineMacula\Laravel\Mfa\Database\TableNames;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentAuthority;
use SineMacula\Laravel\Mfa\Enums\FactorChangeMade;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Events\BootstrapEnrollmentCompleted;
use SineMacula\Laravel\Mfa\Events\FactorConfirmed;
use SineMacula\Laravel\Mfa\Events\FactorRemoved;
use SineMacula\Laravel\Mfa\Events\PasskeyAssociated;
use SineMacula\Laravel\Mfa\Events\RecoveryCodesGenerated;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Exceptions\WriteCanceledException;
use SineMacula\Laravel\Mfa\Lifecycle\FactorRemoval;
use SineMacula\Laravel\Mfa\Lifecycle\RemovalGuard;
use SineMacula\Laravel\Mfa\Lifecycle\RequiredFactorPolicy;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Models\IdentityState;
use SineMacula\Laravel\Mfa\Models\PasskeyAssociation;
use SineMacula\Laravel\Mfa\Models\RecoveryCode;
use SineMacula\Laravel\Mfa\Passkeys\CredentialId;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyAssociationResult;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyAssociations;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyChangeGate;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyRegistration;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Proofs\SessionProofStore;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeIssuance;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService;
use SineMacula\Laravel\Mfa\Requirements\ConfiguredFactorChangeGate;
use SineMacula\Laravel\Mfa\Requirements\ReenrollmentObligation;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Requirements\SessionChange;
use SineMacula\Laravel\Mfa\Requirements\SessionReevaluation;
use SineMacula\Laravel\Mfa\Verification\ProofAcceptance;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Context\FixedPendingSessionResolver;
use Tests\Fixtures\Exceptions\MidRotationFailureException;
use Tests\Fixtures\Factors\UnwrittenFactor;
use Tests\Fixtures\Identities\NonEloquentIdentity;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Lifecycle\FixedFreshnessGate;
use Tests\Fixtures\Lifecycle\RecordingSessionRevoker;
use Tests\Fixtures\Passkeys\Concerns\ArrangesPasskeys;
use Tests\Fixtures\Passkeys\StandInRegistrar;
use Tests\Fixtures\Requirements\FixedIdentityRequirement;
use Tests\Fixtures\Requirements\SignInProofs;
use Tests\Fixtures\Seams\CheckingCompletion;
use Tests\Fixtures\Seams\FreshReauthenticator;
use Tests\Fixtures\Seams\InterruptingProofStore;
use Tests\Fixtures\Seams\RecordingSessionTransition;
use Tests\Fixtures\Seams\RefusingCompletion;
use Tests\TestCase;

/**
 * Runs in the stand-in authentication layer's own transactions, so a refusal
 * rolls back the caller's write and an allowed change commits with it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PasskeyChangeGate::class)]
#[CoversClass(PasskeyAssociationResult::class)]
#[CoversClass(PasskeyAssociations::class)]
#[CoversClass(EnrollmentAuthority::class)]
#[CoversClass(FactorRemoval::class)]
#[CoversClass(SessionReevaluation::class)]
#[CoversClass(RecoveryCodeIssuance::class)]
#[CoversClass(ProofAcceptance::class)]
#[CoversClass(ReenrollmentObligation::class)]
#[CoversClass(RemovalGuard::class)]
#[CoversClass(RequiredFactorPolicy::class)]
final class PasskeyChangeGateTest extends TestCase
{
    use ArrangesPasskeys;

    /**
     * Fakes the gate's events and makes recovery codes quick to hash.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        config()->set('hashing.bcrypt.rounds', 4);

        Event::fake([PasskeyAssociated::class, FactorConfirmed::class, FactorRemoved::class, RecoveryCodesGenerated::class]);
    }

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Throwable
     */
    public function testEveryCallIsRefusedOutsideATransaction(): void
    {
        $this->enablePasskeys();

        $user = $this->signedInPerson();
        $gate = $this->gate();

        foreach (
            [
                fn () => $gate->registering(Callers::of($user, self::APPLICATION), $this->registration($user)),
                static function () use ($gate, $user): void {
                    $gate->removing(Callers::of($user, self::APPLICATION), self::CREDENTIAL);
                },
            ] as $call
        ) {
            try {
                $call();
                self::fail('A call outside a transaction was expected to be refused.');
            } catch (\LogicException $exception) {
                self::assertSame('The passkey change gate runs only inside the caller\'s transaction on the storage connection.', $exception->getMessage());
            }
        }
    }

    /**
     * On an application without passkeys, or for a non-person identity, the
     * registration goes on as a sign-in passkey only.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testNothingIsAssociatedWithoutThePasskeyTypeOrForAMachine(): void
    {
        $this->enablePasskeys(['types' => ['totp']]);

        $user = $this->signedInPerson();

        self::assertNull($this->registrar()->register($user, self::APPLICATION, $this->registration($user)));
        self::assertTrue(StandInRegistrar::stores($user, self::CREDENTIAL));

        $this->enablePasskeys();

        $machine = new NonEloquentIdentity('machine-1', person: false);

        $result = DB::transaction(fn () => $this->gate()->registering(Callers::of($machine, self::APPLICATION), $this->registration($user, self::OTHER_CREDENTIAL)));

        self::assertNull($result);

        self::assertSame(0, Factor::query()->count());
        self::assertSame(0, PasskeyAssociation::query()->count());
        Event::assertNotDispatched(PasskeyAssociated::class);
    }

    /**
     * The default reauthenticator refuses a first passkey on an active session.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefusedRegistrationRollsBackTheCallersCredential(): void
    {
        $this->enablePasskeys();

        $user = $this->signedInPerson();

        self::assertSame(FailureReason::NOT_FRESH, $this->refusal(fn () => $this->registrar()->register($user, self::APPLICATION, $this->registration($user))));
        self::assertFalse(StandInRegistrar::stores($user, self::CREDENTIAL));
        self::assertSame(0, Factor::query()->count());
        self::assertSame(0, PasskeyAssociation::query()->count());
        Event::assertNotDispatched(PasskeyAssociated::class);
        Event::assertNotDispatched(FactorConfirmed::class);
    }

    /**
     * With the first factor proved again it is confirmed and reported once the
     * caller commits.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFirstPasskeyIsAssociatedWithItsRecoveryCodes(): void
    {
        $this->enablePasskeys(['recovery_codes' => ['enabled' => true]]);
        $this->reauthenticate();

        $user   = $this->signedInPerson();
        $result = $this->registrar()->register($user, self::APPLICATION, $this->registration($user), null);

        $factor = Factor::query()->sole();

        self::assertInstanceOf(PasskeyAssociationResult::class, $result);
        self::assertSame($factor->id, $result->factor->id);
        self::assertSame('passkey', $result->factor->type);
        self::assertTrue($factor->isConfirmed());
        self::assertSame(self::CREDENTIAL, $factor->credential_reference);
        self::assertSame(self::APPLICATION, $factor->application);
        self::assertCount(10, $result->recoveryCodes);
        self::assertSame(10, RecoveryCode::query()->count());
        self::assertTrue(StandInRegistrar::stores($user, self::CREDENTIAL));

        $association = PasskeyAssociation::query()->sole();

        self::assertSame($factor->id, $association->factor_id);
        self::assertSame(self::CREDENTIAL, $association->credential_id);
        self::assertSame(hash('sha256', self::CREDENTIAL), $association->credential_id_hash);

        Event::assertDispatched(PasskeyAssociated::class, static fn (PasskeyAssociated $event): bool => $event->factor->id === $factor->id);
        Event::assertDispatched(FactorConfirmed::class, static fn (FactorConfirmed $event): bool => $event->factor->id === $factor->id);
        Event::assertDispatched(RecoveryCodesGenerated::class);
    }

    /**
     * Only when accepted and the session then meets their level.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testNoRecoveryCodesBelowTheLevelOrWhenNotAccepted(): void
    {
        $this->enablePasskeys(['recovery_codes' => ['enabled' => true, 'level' => 'aal3']]);
        $this->reauthenticate();

        $user = $this->signedInPerson();

        self::assertSame([], $this->registrar()->register($user, self::APPLICATION, $this->registration($user))?->recoveryCodes);

        $this->enablePasskeys();

        $other = $this->signedInPerson('other@example.test');

        self::assertSame([], $this->registrar()->register($other, self::APPLICATION, $this->registration($other, self::OTHER_CREDENTIAL))?->recoveryCodes);
        self::assertSame(0, RecoveryCode::query()->count());
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testAStaleReauthenticationIsRefused(): void
    {
        $this->enablePasskeys();
        $this->reauthenticate(ConfiguredFactorChangeGate::REAUTHENTICATION_MAX_AGE + 1);

        $user = $this->signedInPerson();

        self::assertSame(FailureReason::NOT_FRESH, $this->refusal(fn () => $this->registrar()->register($user, self::APPLICATION, $this->registration($user))));
    }

    /**
     * A reauthentication is not enough.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFurtherPasskeyNeedsAFreshStepUp(): void
    {
        $this->enablePasskeys();
        $reauthenticator = $this->reauthenticate();

        $user = $this->signedInPerson();
        $totp = $this->confirmedFactor($user);

        self::assertSame(FailureReason::NOT_FRESH, $this->refusal(fn () => $this->registrar()->register($user, self::APPLICATION, $this->registration($user))));

        $this->stepUpWith($user, $totp);

        self::assertNotNull($this->registrar()->register($user, self::APPLICATION, $this->registration($user)));
        self::assertSame(0, $reauthenticator->asked);
    }

    /**
     * Only when the application allows it and the identity has no factor.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPendingSessionAssociatesThroughBootstrapOnly(): void
    {
        $this->enablePasskeys(['bootstrap' => ['enabled' => true, 'types' => ['passkey']]]);

        $user = $this->signedInPerson();

        $this->pending($user, [PendingAction::LIST_FACTORS]);

        self::assertSame(
            FailureReason::NOT_FOUND,
            $this->refusal(fn () => $this->registrar()->register($user, self::APPLICATION, $this->registration($user, session: 'pending-1'))),
        );

        $this->pending($user, [PendingAction::CONFIRM_BOOTSTRAP_ENROLLMENT]);

        self::assertNotNull($this->registrar()->register($user, self::APPLICATION, $this->registration($user, session: 'pending-1')));

        self::assertSame(
            FailureReason::NOT_FRESH,
            $this->refusal(fn () => $this->registrar()->register($user, self::APPLICATION, $this->registration($user, self::OTHER_CREDENTIAL, session: 'pending-1'))),
        );
    }

    /**
     * The application's limit on confirmed factors of a type.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheLimitsApply(): void
    {
        $this->enablePasskeys(['limits' => ['confirmed_per_type' => 1]]);

        $user    = $this->signedInPerson();
        $passkey = $this->confirmedFactor($user, 'passkey', self::OTHER_CREDENTIAL);

        $this->stepUpWith($user, $passkey);

        self::assertSame(FailureReason::LIMIT_REACHED, $this->refusal(fn () => $this->registrar()->register($user, self::APPLICATION, $this->registration($user))));
    }

    /**
     * Whichever identity holds it: a registration is never idempotent.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACredentialAssociatedAlreadyIsRefused(): void
    {
        $this->enablePasskeys();
        $this->reauthenticate();

        $owner = $this->signedInPerson('owner@example.test');

        $this->registrar()->register($owner, self::APPLICATION, $this->registration($owner));

        self::assertSame(FailureReason::CREDENTIAL_ASSOCIATED, $this->refusal(fn () => $this->registrar()->register($owner, self::APPLICATION, $this->registration($owner))));

        $intruder = $this->signedInPerson('intruder@example.test');

        self::assertSame(FailureReason::CREDENTIAL_ASSOCIATED, $this->refusal(fn () => $this->registrar()->register($intruder, self::APPLICATION, $this->registration($intruder))));
        self::assertSame(1, PasskeyAssociation::query()->count());
    }

    /**
     * The unique credential index refuses it and the registration rolls back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACredentialAssociatedConcurrentlyIsRefused(): void
    {
        $this->enablePasskeys();
        $this->reauthenticate();

        $user = $this->signedInPerson();

        Factor::created(static function (): void {
            // Another identity commits it between this check and the insert.
            DB::table(TableNames::of(TableNames::PASSKEY_ASSOCIATIONS))->insert([
                'id'                   => (string) Str::ulid(),
                'factor_id'            => 'concurrent-factor',
                'authenticatable_type' => 'concurrent',
                'authenticatable_id'   => 'concurrent',
                'credential_id_hash'   => CredentialId::hash(self::CREDENTIAL),
                'credential_id'        => self::CREDENTIAL,
            ]);
        });

        self::assertSame(FailureReason::CREDENTIAL_ASSOCIATED, $this->refusal(fn () => $this->registrar()->register($user, self::APPLICATION, $this->registration($user))));
        self::assertFalse(StandInRegistrar::stores($user, self::CREDENTIAL));
        self::assertSame(0, Factor::query()->count());
    }

    /**
     * Bound to another session, without user presence, or for another identity.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARegistrationMustBeTheCallersOwn(): void
    {
        $this->enablePasskeys();
        $this->reauthenticate();

        $user  = $this->signedInPerson();
        $other = TestUser::query()->create(['email' => 'other@example.test']);

        self::assertSame(
            FailureReason::NOT_FOUND,
            $this->refusal(fn () => $this->registrar()->register($user, self::APPLICATION, $this->registration($user, session: 'another-sign-in'))),
        );
        self::assertSame(
            FailureReason::INVALID_CODE,
            $this->refusal(fn () => $this->registrar()->register($user, self::APPLICATION, $this->registration($user, properties: ObservedProperties::none()))),
        );
        self::assertSame(FailureReason::NOT_FOUND, $this->refusal(fn () => $this->registrar()->register($other, self::APPLICATION, $this->registration($other))));
        self::assertSame(0, PasskeyAssociation::query()->count());
    }

    /**
     * The caller's credential rolls back with the refusal.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnInactiveIdentityRegistersNothing(): void
    {
        $this->enablePasskeys();

        $identity = new NonEloquentIdentity('plain-1', active: false);
        $owner    = ProofOwner::of($identity);

        $this->actingAs($identity);

        $this->container()->make(ProofStore::class)->begin($identity, self::APPLICATION, self::SESSION);

        $this->reauthenticate();

        $registration = new PasskeyRegistration(
            self::CREDENTIAL,
            new ObservedProperties(userPresence: true),
            new ProofBinding($owner->type, $owner->key, self::APPLICATION, self::SESSION, Purpose::ENROLLMENT),
        );

        self::assertSame(FailureReason::IDENTITY_INACTIVE, $this->refusal(fn () => $this->registrar()->register($identity, self::APPLICATION, $registration)));
        self::assertFalse(StandInRegistrar::stores($identity, self::CREDENTIAL));
        self::assertSame(0, Factor::query()->count());
        self::assertSame(0, PasskeyAssociation::query()->count());
    }

    /**
     * No factor, association, recovery code or event is left behind.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACallerFailureAfterAnAllowedGateLeavesNothing(): void
    {
        $this->enablePasskeys(['recovery_codes' => ['enabled' => true]]);
        $this->reauthenticate();

        $user = $this->signedInPerson();

        try {
            $this->registrar()->register($user, self::APPLICATION, $this->registration($user), static function (): void {
                throw new MidRotationFailureException('The caller failed after the gate.');
            });
            self::fail('The caller\'s failure was expected to propagate.');
        } catch (MidRotationFailureException) {
            // Expected.
        }

        self::assertSame(0, Factor::query()->count());
        self::assertSame(0, PasskeyAssociation::query()->count());
        self::assertSame(0, RecoveryCode::query()->count());
        self::assertFalse(StandInRegistrar::stores($user, self::CREDENTIAL));
        Event::assertNothingDispatched();
    }

    /**
     * Whatever the session's freshness.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRemovingAnUnassociatedCredentialIsANoOp(): void
    {
        $this->enablePasskeys();

        $user = $this->signedInPerson();
        $totp = $this->confirmedFactor($user);

        $this->registrar()->remove($user, self::APPLICATION, self::CREDENTIAL);

        self::assertTrue(Factor::query()->whereKey($totp->id)->exists());
        Event::assertNotDispatched(FactorRemoved::class);
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testRemovingNeedsAFreshStepUp(): void
    {
        $this->enablePasskeys();

        $user    = $this->signedInPerson();
        $passkey = $this->confirmedFactor($user, 'passkey', self::CREDENTIAL);

        self::assertSame(FailureReason::NOT_FRESH, $this->refusal(function () use ($user): void {
            $this->registrar()->remove($user, self::APPLICATION, self::CREDENTIAL);
        }));
        self::assertTrue(Factor::query()->whereKey($passkey->id)->exists());
    }

    /**
     * The shortfall goes to the session transition.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARemovalLeavingTheSessionShortReturnsItToPending(): void
    {
        $this->enablePasskeys();

        $transition = new RecordingSessionTransition;

        $this->container()->instance(SessionTransition::class, $transition);
        $this->container()->instance(IdentityRequirement::class, new FixedIdentityRequirement(Requirement::none()->withPhishingResistance()));

        $user    = $this->signedInPerson();
        $totp    = $this->confirmedFactor($user);
        $passkey = $this->confirmedFactor($user, 'passkey', self::CREDENTIAL);

        $this->stepUpWith($user, $totp);

        $this->registrar()->remove($user, self::APPLICATION, self::CREDENTIAL);

        self::assertFalse(Factor::query()->whereKey($passkey->id)->exists());
        self::assertCount(1, $transition->shortfalls());
        self::assertSame(FactorChangeMade::REMOVED, $transition->changes[0]->change);
        self::assertSame($passkey->id, $transition->changes[0]->factor->id);
    }

    /**
     * Such a revoker is the only judge of a passkey removal too.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARevokerThatJudgesTheSessionReturnsItsResultFromRemoving(): void
    {
        $this->enablePasskeys();

        $transition = new RecordingSessionTransition;
        $completion = new \stdClass;

        $this->container()->instance(SessionTransition::class, $transition);
        $this->container()->instance(SessionRevoker::class, new RecordingSessionRevoker(judges: true, completion: $completion));
        $this->container()->instance(IdentityRequirement::class, new FixedIdentityRequirement(Requirement::none()->withPhishingResistance()));

        $user = $this->signedInPerson();
        $totp = $this->confirmedFactor($user);

        $this->confirmedFactor($user, 'passkey', self::CREDENTIAL);
        $this->stepUpWith($user, $totp);

        self::assertSame($completion, DB::transaction(fn (): ?object => $this->gate()->removing(Callers::of($user, self::APPLICATION), self::CREDENTIAL)));
        self::assertSame([], $transition->changes);
        self::assertNull(DB::transaction(fn (): ?object => $this->gate()->removing(Callers::of($user, self::APPLICATION), self::CREDENTIAL)));
    }

    /**
     * While another factor remains, a step-up with the passkey being removed is
     * refused and one with the other factor is accepted.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRemovingNeedsAStepUpMadeWithAnotherFactor(): void
    {
        $this->enablePasskeys(['recovery_codes' => ['enabled' => true]]);

        $transition = new RecordingSessionTransition;

        $this->container()->instance(SessionTransition::class, $transition);

        $user    = $this->signedInPerson();
        $totp    = $this->confirmedFactor($user);
        $passkey = $this->confirmedFactor($user, 'passkey', self::CREDENTIAL);

        $this->container()->make(RecoveryCodeService::class)->generate($user, 'web');

        $this->stepUpWith($user, $passkey);

        self::assertSame(FailureReason::NOT_FRESH, $this->refusal(function () use ($user): void {
            $this->registrar()->remove($user, self::APPLICATION, self::CREDENTIAL);
        }));

        $this->stepUpWith($user, $totp);

        $this->registrar()->remove($user, self::APPLICATION, self::CREDENTIAL);

        self::assertFalse(Factor::query()->whereKey($passkey->id)->exists());
        self::assertSame(0, PasskeyAssociation::query()->count());
        self::assertTrue(Factor::query()->whereKey($totp->id)->exists());
        self::assertSame(10, RecoveryCode::query()->count());
        self::assertCount(1, $transition->changes);
        self::assertSame([], $transition->shortfalls());
        Event::assertDispatched(FactorRemoved::class, static fn (FactorRemoved $event): bool => $event->factor->id === $passkey->id);
    }

    /**
     * The recovery codes go with it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheOnlyFactorMayBeRemovedWhenNoneIsRequired(): void
    {
        $this->enablePasskeys(['recovery_codes' => ['enabled' => true]]);

        $user    = $this->signedInPerson();
        $passkey = $this->confirmedFactor($user, 'passkey', self::CREDENTIAL);

        $this->container()->make(RecoveryCodeService::class)->generate($user, 'web');
        $this->stepUpWith($user, $passkey);

        $this->registrar()->remove($user, self::APPLICATION, self::CREDENTIAL);

        self::assertSame(0, Factor::query()->count());
        self::assertSame(0, RecoveryCode::query()->count());
    }

    /**
     * The caller's own removal rolls back with the refusal.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheLastAcceptableFactorIsKeptWhileOneIsRequired(): void
    {
        $this->enablePasskeys(['requirement' => 'always']);

        $user    = $this->signedInPerson();
        $passkey = $this->confirmedFactor($user, 'passkey', self::CREDENTIAL);

        DB::table(StandInRegistrar::TABLE)->insert(['owner' => ProofOwner::of($user)->key, 'credential_id' => self::CREDENTIAL]);

        $this->stepUpWith($user, $passkey);

        self::assertSame(FailureReason::LAST_FACTOR, $this->refusal(function () use ($user): void {
            $this->registrar()->remove($user, self::APPLICATION, self::CREDENTIAL);
        }));
        self::assertTrue(Factor::query()->whereKey($passkey->id)->exists());
        self::assertTrue(StandInRegistrar::stores($user, self::CREDENTIAL));
    }

    /**
     * It is not found, since an application never deletes another's factor.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFactorOfAnotherApplicationIsNotRemoved(): void
    {
        $this->enablePasskeys();

        $user    = $this->signedInPerson();
        $passkey = $this->confirmedFactor($user, 'passkey', self::CREDENTIAL);

        $passkey->update(['application' => 'another-application']);

        DB::table(StandInRegistrar::TABLE)->insert(['owner' => ProofOwner::of($user)->key, 'credential_id' => self::CREDENTIAL]);

        $this->stepUpWith($user, $passkey);

        self::assertSame(FailureReason::NOT_FOUND, $this->refusal(function () use ($user): void {
            $this->registrar()->remove($user, self::APPLICATION, self::CREDENTIAL);
        }));
        self::assertTrue(Factor::query()->whereKey($passkey->id)->exists());
        self::assertTrue(StandInRegistrar::stores($user, self::CREDENTIAL));
    }

    /**
     * As through `Mfa::removeFactor()`; the caller's removal rolls back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnInactiveIdentityIsNotRemovedFrom(): void
    {
        $this->enablePasskeys();

        $identity = new NonEloquentIdentity('plain-1', active: false);
        $owner    = ProofOwner::of($identity);

        $this->actingAs($identity);

        $this->container()->make(ProofStore::class)->begin($identity, self::APPLICATION, self::SESSION);

        /** @var \SineMacula\Laravel\Mfa\Models\Factor $passkey */
        $passkey = Factor::query()->create([
            'authenticatable_type' => $owner->type,
            'authenticatable_id'   => $owner->key,
            'type'                 => 'passkey',
            'status'               => 'confirmed',
            'confirmed_at'         => CarbonImmutable::now(),
            'credential_reference' => self::CREDENTIAL,
            'application'          => self::APPLICATION,
        ]);

        PasskeyAssociation::query()->create([
            'factor_id'            => $passkey->id,
            'authenticatable_type' => $owner->type,
            'authenticatable_id'   => $owner->key,
            'credential_id_hash'   => CredentialId::hash(self::CREDENTIAL),
            'credential_id'        => self::CREDENTIAL,
        ]);

        DB::table(StandInRegistrar::TABLE)->insert(['owner' => $owner->key, 'credential_id' => self::CREDENTIAL]);

        self::assertSame(FailureReason::IDENTITY_INACTIVE, $this->refusal(function () use ($identity): void {
            $this->registrar()->remove($identity, self::APPLICATION, self::CREDENTIAL);
        }));
        self::assertTrue(Factor::query()->whereKey($passkey->id)->exists());
        self::assertTrue(StandInRegistrar::stores($identity, self::CREDENTIAL));
    }

    /**
     * Whatever proofs the new one holds, the factor and the credential stay.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASignInChangedBeforeTheLockRemovesNothing(): void
    {
        $this->enablePasskeys();

        $user    = $this->signedInPerson();
        $passkey = $this->confirmedFactor($user, 'passkey', self::CREDENTIAL);

        DB::table(StandInRegistrar::TABLE)->insert(['owner' => ProofOwner::of($user)->key, 'credential_id' => self::CREDENTIAL]);

        $this->stepUpWith($user, $passkey);

        $this->container()->instance(ProofStore::class, new InterruptingProofStore($this->container()->make(ProofStore::class), 1, 'sign-in-b'));

        self::assertSame(FailureReason::NOT_FOUND, $this->refusal(function () use ($user): void {
            $this->registrar()->remove($user, self::APPLICATION, self::CREDENTIAL);
        }));
        self::assertTrue(Factor::query()->whereKey($passkey->id)->exists());
        self::assertTrue(StandInRegistrar::stores($user, self::CREDENTIAL));
    }

    /**
     * With nothing to compare under the lock, a bound gate answering fresh
     * removes nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testNoSignInTheStoreKnowsIsNotFresh(): void
    {
        $this->enablePasskeys();

        /** @var \Tests\Fixtures\Identities\TestUser $user */
        $user    = TestUser::query()->create(['email' => 'person@example.test']);
        $passkey = $this->confirmedFactor($user, 'passkey', self::CREDENTIAL);

        $this->actingAs($user);

        DB::table(StandInRegistrar::TABLE)->insert(['owner' => ProofOwner::of($user)->key, 'credential_id' => self::CREDENTIAL]);

        $this->container()->instance(FreshnessGate::class, new FixedFreshnessGate(Requirement::none()->withAdditionalVerification(60)));

        self::assertSame(FailureReason::NOT_FRESH, $this->refusal(function () use ($user): void {
            $this->registrar()->remove($user, self::APPLICATION, self::CREDENTIAL);
        }));
        self::assertTrue(Factor::query()->whereKey($passkey->id)->exists());
        self::assertTrue(StandInRegistrar::stores($user, self::CREDENTIAL));
    }

    /**
     * The current session keeps its proofs but the removed factor's.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRemovingRevokesTheOtherSessionsAndKeepsTheCurrentOnesOtherProofs(): void
    {
        $this->enablePasskeys();

        $user    = $this->signedInPerson();
        $totp    = $this->confirmedFactor($user);
        $passkey = $this->confirmedFactor($user, 'passkey', self::CREDENTIAL);
        $other   = new SessionProofStore(new Store('other-device', new ArraySessionHandler(10)));

        $other->begin($user, self::APPLICATION, 'other-sign-in');
        $other->record($user, SignInProofs::of($user)->inSession('other-sign-in')->totp());

        $this->stepUpWith($user, $passkey);
        $this->stepUpWith($user, $totp);

        $this->registrar()->remove($user, self::APPLICATION, self::CREDENTIAL);

        $kept = array_map(static fn (Proof $proof): ?string => $proof->reference, $this->container()->make(ProofStore::class)->proofs($user, self::APPLICATION, self::SESSION));

        self::assertSame([], $other->proofs($user, self::APPLICATION, 'other-sign-in'));
        self::assertSame([$totp->id], $kept);
    }

    /**
     * Another identity's sign-in does not own the credential, and an
     * application with no sign-in has nothing to step up on.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARemovalForAnotherIdentityOrApplicationRemovesNothing(): void
    {
        $this->enablePasskeys();

        $user  = $this->signedInPerson();
        $other = TestUser::query()->create(['email' => 'other@example.test']);

        $this->confirmedFactor($user, 'passkey', self::CREDENTIAL);
        $this->container()->make(ProofStore::class)->begin($other, self::APPLICATION, 'other-sign-in');

        $remove = fn (CallerContext $caller): \Closure => fn () => DB::transaction(fn () => $this->gate()->removing($caller, self::CREDENTIAL));

        self::assertSame(FailureReason::NOT_FOUND, $this->refusal($remove(CallerContext::forIdentity($other, self::APPLICATION))));
        self::assertSame(FailureReason::NOT_FRESH, $this->refusal($remove(CallerContext::forIdentity($user, 'another-application'))));
        self::assertSame(1, PasskeyAssociation::query()->count());
    }

    /**
     * Refused as not found; the other identity's factor and association stay.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRemovingAnotherIdentitysCredentialIsRefused(): void
    {
        $this->enablePasskeys();

        $user = $this->signedInPerson();

        /** @var \Tests\Fixtures\Identities\TestUser $other */
        $other   = TestUser::query()->create(['email' => 'other@example.test']);
        $passkey = $this->confirmedFactor($other, 'passkey', self::CREDENTIAL);

        self::assertSame(FailureReason::NOT_FOUND, $this->refusal(fn () => DB::transaction(function () use ($user): void {
            $this->gate()->removing(Callers::of($user, self::APPLICATION), self::CREDENTIAL);
        })));
        self::assertTrue(Factor::query()->whereKey($passkey->id)->exists());
        self::assertSame($passkey->id, PasskeyAssociation::query()->sole()->factor_id);
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testThePasskeyFactorCarriesItsLabel(): void
    {
        $this->enablePasskeys();
        $this->reauthenticate();

        $user = $this->signedInPerson();

        DB::transaction(function () use ($user): void {
            $this->gate()->registering(Callers::of($user, self::APPLICATION), $this->registration($user), 'Work laptop');
        });

        self::assertSame('Work laptop', Factor::query()->sole()->label);
    }

    /**
     * A persistence seam that neither writes the factor nor throws.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFactorThatWasNotWrittenIsNotAssociated(): void
    {
        $this->enablePasskeys();
        $this->reauthenticate();

        $user = $this->signedInPerson();

        config()->set('mfa.factor.model', UnwrittenFactor::class);

        $this->expectException(WriteCanceledException::class);
        $this->expectExceptionMessage('the passkey was not associated');

        DB::transaction(function () use ($user): void {
            $this->gate()->registering(Callers::of($user, self::APPLICATION), $this->registration($user));
        });
    }

    /**
     * Nothing binds the registration, so it is refused as not found.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARegistrationWithoutASignInIsRefused(): void
    {
        $this->enablePasskeys();
        $this->reauthenticate();

        /** @var \Tests\Fixtures\Identities\TestUser $user */
        $user = TestUser::query()->create(['email' => 'person@example.test']);

        $this->actingAs($user);

        self::assertSame(FailureReason::NOT_FOUND, $this->refusal(fn () => $this->registrar()->register($user, self::APPLICATION, $this->registration($user))));
        self::assertSame(0, PasskeyAssociation::query()->count());
    }

    /**
     * A refusal anywhere rolls all of it back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSequencesInOneOuterTransactionCommitOrRollBackTogether(): void
    {
        $this->enablePasskeys();

        $user = $this->signedInPerson();
        $totp = $this->confirmedFactor($user);

        $this->stepUpWith($user, $totp);

        DB::transaction(function () use ($user): void {
            $this->gate()->registering(Callers::of($user, self::APPLICATION), $this->registration($user));
            $this->gate()->removing(Callers::of($user, self::APPLICATION), self::CREDENTIAL);
        });

        self::assertSame([$totp->id], Factor::query()->pluck('id')->all());
        self::assertSame(0, PasskeyAssociation::query()->count());
        Event::assertDispatched(PasskeyAssociated::class);
        Event::assertDispatched(FactorRemoved::class);

        $refusal = $this->refusal(fn () => DB::transaction(function () use ($user): bool {
            $this->gate()->registering(Callers::of($user, self::APPLICATION), $this->registration($user, self::OTHER_CREDENTIAL));
            $this->gate()->registering(Callers::of($user, self::APPLICATION), $this->registration($user, self::OTHER_CREDENTIAL));

            return true;
        }));

        self::assertSame(FailureReason::CREDENTIAL_ASSOCIATED, $refusal);
        self::assertSame([$totp->id], Factor::query()->pluck('id')->all());
        self::assertSame(0, PasskeyAssociation::query()->count());
    }

    /**
     * It reports its own event, ends the obligation and returns the
     * completion's result.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABootstrapRegistrationCompletesThePendingSession(): void
    {
        Event::fake([BootstrapEnrollmentCompleted::class, FactorConfirmed::class, PasskeyAssociated::class]);

        $this->enablePasskeys(['bootstrap' => ['enabled' => true, 'types' => ['passkey']]]);

        $user = $this->signedInPerson();
        $seam = new CheckingCompletion('pending-1', completion: new \stdClass);

        $this->obligeToEnroll($user);
        $this->pending($user, [PendingAction::CONFIRM_BOOTSTRAP_ENROLLMENT]);
        $this->container()->instance(PendingCompletion::class, $seam);

        $result = $this->registrar()->register($user, self::APPLICATION, $this->registration($user, session: 'pending-1'));

        self::assertNotNull($result);
        self::assertNotNull($result->verification);
        self::assertSame('passkey', $result->verification->type);
        self::assertSame(Purpose::ENROLLMENT, $result->verification->proof?->binding->purpose);
        self::assertNotNull($result->verification->completion());
        self::assertCount(1, $seam->accepted);
        self::assertFalse(ReenrollmentObligation::isRequired($user));

        Event::assertDispatched(BootstrapEnrollmentCompleted::class);
    }

    /**
     * It ends the obligation too and goes to the bound transition with nothing
     * outstanding.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnActiveRegistrationIsNoBootstrap(): void
    {
        Event::fake([BootstrapEnrollmentCompleted::class, FactorConfirmed::class, PasskeyAssociated::class]);

        $this->enablePasskeys();

        $completion = new \stdClass;
        $transition = new RecordingSessionTransition($completion);

        $this->container()->instance(SessionTransition::class, $transition);

        $user = $this->signedInPerson();

        $this->obligeToEnroll($user);
        $this->reauthenticate();

        $result = $this->registrar()->register($user, self::APPLICATION, $this->registration($user));

        self::assertNotNull($result);
        self::assertNull($result->verification);
        self::assertFalse(ReenrollmentObligation::isRequired($user));
        self::assertSame($completion, $result->completion());
        self::assertCount(1, $transition->changes);
        self::assertSame(FactorChangeMade::PASSKEY_REGISTERED, $transition->changes[0]->change);
        self::assertNull($transition->changes[0]->outstanding);

        Event::assertNotDispatched(BootstrapEnrollmentCompleted::class);
    }

    /**
     * Evaluated as any other first factor.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnActiveFirstPasskeyLeavingTheSessionShortGoesToTheTransition(): void
    {
        $this->enablePasskeys(['requirement' => 'enrolled']);

        $completion = new \stdClass;
        $transition = new RecordingSessionTransition($completion);

        $this->container()->instance(SessionTransition::class, $transition);

        $user = $this->signedInPerson();

        $this->reauthenticate();

        $result = $this->registrar()->register($user, self::APPLICATION, $this->registration($user));

        self::assertNotNull($result);
        self::assertNull($result->verification);
        self::assertSame($completion, $result->completion());
        self::assertCount(1, $transition->shortfalls());

        $change = $transition->changes[0];

        self::assertSame(FactorChangeMade::PASSKEY_REGISTERED, $change->change);
        self::assertSame(self::APPLICATION, $change->application);
        self::assertSame($this->container()->make(ProofStore::class)->currentSession($user, self::APPLICATION), $change->session);
        self::assertSame($result->factor->id, $change->factor->id);
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testATransitionsRefusalRollsTheRegistrationBack(): void
    {
        $this->enablePasskeys(['requirement' => 'enrolled']);

        $this->container()->instance(SessionTransition::class, new class implements SessionTransition {
            /**
             * @param  \SineMacula\Laravel\Mfa\Requirements\SessionChange  $change
             * @return ?object
             *
             * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
             */
            #[\Override]
            public function factorChanged(SessionChange $change): ?object
            {
                throw new OperationRefusedException(FailureReason::NOT_ACCEPTED, 'The session refused it.');
            }
        });

        $user = $this->signedInPerson();

        $this->reauthenticate();

        try {
            $this->registrar()->register($user, self::APPLICATION, $this->registration($user));

            self::fail('The refusal was expected to propagate.');
        } catch (OperationRefusedException $exception) {
            self::assertSame(FailureReason::NOT_ACCEPTED, $exception->reason);
        }

        self::assertSame(0, Factor::query()->count());
        self::assertSame(0, PasskeyAssociation::query()->count());
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testACompletionsRefusalRollsTheRegistrationBack(): void
    {
        $this->enablePasskeys(['bootstrap' => ['enabled' => true, 'types' => ['passkey']]]);

        $user = $this->signedInPerson();

        $this->obligeToEnroll($user);
        $this->pending($user, [PendingAction::CONFIRM_BOOTSTRAP_ENROLLMENT]);
        $this->container()->instance(PendingCompletion::class, new RefusingCompletion(new OperationRefusedException(FailureReason::NOT_ACCEPTED, 'The session refused it.')));

        self::assertSame(
            FailureReason::NOT_ACCEPTED,
            $this->refusal(fn () => $this->registrar()->register($user, self::APPLICATION, $this->registration($user, session: 'pending-1'))),
        );

        self::assertSame(0, Factor::query()->count());
        self::assertFalse(StandInRegistrar::stores($user, self::CREDENTIAL));
        self::assertTrue(ReenrollmentObligation::isRequired($user));
    }

    /**
     * Between the first look and the lock.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASignInChangedBeforeTheLockRegistersNothing(): void
    {
        $this->enablePasskeys();

        $user = $this->signedInPerson();

        $this->reauthenticate();
        $this->container()->instance(ProofStore::class, new InterruptingProofStore($this->container()->make(ProofStore::class), 1, 'sign-in-b'));

        self::assertSame(
            FailureReason::NOT_FOUND,
            $this->refusal(fn () => $this->registrar()->register($user, self::APPLICATION, $this->registration($user))),
        );
        self::assertSame(0, Factor::query()->count());
    }

    /**
     * Binds a reauthenticator that proved the password `$secondsAgo` ago.
     *
     * @param  int  $secondsAgo
     * @return \Tests\Fixtures\Seams\FreshReauthenticator
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function reauthenticate(int $secondsAgo = 0): FreshReauthenticator
    {
        $reauthenticator = new FreshReauthenticator($this->container()->make(ProofStore::class), $secondsAgo);

        $this->container()->instance(Reauthenticator::class, $reauthenticator);

        return $reauthenticator;
    }

    /**
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @return void
     */
    private function obligeToEnroll(TestUser $user): void
    {
        $owner = ProofOwner::of($user);

        IdentityState::query()->updateOrCreate(
            ['authenticatable_type' => $owner->type, 'authenticatable_id' => $owner->key],
            ['reenrollment_required' => true],
        );
    }

    /**
     * Every request carries a pending session of the user's for `$actions`.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @param  list<\SineMacula\Laravel\Mfa\Enums\PendingAction>  $actions
     * @return void
     */
    private function pending(TestUser $user, array $actions): void
    {
        $proofs = SignInProofs::of($user)->inSession('pending-1');

        $this->container()->instance(PendingSessionResolver::class, new FixedPendingSessionResolver(
            new PendingContext(
                $user,
                self::APPLICATION,
                'pending-1',
                $proofs->password(),
                Requirement::none()->withAdditionalVerification(),
                $actions,
                CarbonImmutable::now()->addHour(),
            ),
        ));

        $this->container()->make(ProofStore::class)->begin($user, self::APPLICATION, 'pending-1');
    }

    /**
     * @param  \Closure(): mixed  $call
     * @return \SineMacula\Laravel\Mfa\Enums\FailureReason
     */
    private function refusal(\Closure $call): FailureReason
    {
        try {
            $call();
        } catch (OperationRefusedException $exception) {
            return $exception->reason;
        }

        self::fail('The call was expected to be refused.');
    }

    /**
     * @return \Tests\Fixtures\Passkeys\StandInRegistrar
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function registrar(): StandInRegistrar
    {
        return new StandInRegistrar($this->gate());
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Passkeys\PasskeyChangeGate
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function gate(): PasskeyChangeGate
    {
        return $this->container()->make(PasskeyChangeGate::class);
    }
}
