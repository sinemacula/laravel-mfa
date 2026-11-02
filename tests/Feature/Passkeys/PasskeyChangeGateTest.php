<?php

declare(strict_types = 1);

namespace Tests\Feature\Passkeys;

use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Assurance\ObservedProperties;
use SineMacula\Laravel\Mfa\Context\PendingContext;
use SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Contracts\Reauthenticator;
use SineMacula\Laravel\Mfa\Contracts\SessionTransition;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentAuthority;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Events\FactorConfirmed;
use SineMacula\Laravel\Mfa\Events\FactorRemoved;
use SineMacula\Laravel\Mfa\Events\PasskeyAssociated;
use SineMacula\Laravel\Mfa\Events\RecoveryCodesGenerated;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Lifecycle\FactorRemoval;
use SineMacula\Laravel\Mfa\Lifecycle\RequiredFactorPolicy;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Models\PasskeyAssociation;
use SineMacula\Laravel\Mfa\Models\RecoveryCode;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyAssociationResult;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyChangeGate;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Proofs\SessionProofStore;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use Tests\Fixtures\Context\FixedPendingSessionResolver;
use Tests\Fixtures\Exceptions\MidRotationFailureException;
use Tests\Fixtures\Identities\NonEloquentIdentity;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Passkeys\Concerns\ArrangesPasskeys;
use Tests\Fixtures\Passkeys\StandInRegistrar;
use Tests\Fixtures\Requirements\SignInProofs;
use Tests\Fixtures\Seams\FreshReauthenticator;
use Tests\Fixtures\Seams\RecordingSessionTransition;
use Tests\TestCase;

/**
 * Feature tests for `PasskeyChangeGate`, run in the stand-in authentication
 * layer's own transactions on SQLite: a registration, removal or change the
 * gate refuses rolls back the caller's own write with it, and one the gate
 * allows commits, or rolls back with the caller, as one change.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PasskeyChangeGate::class)]
#[CoversClass(PasskeyAssociationResult::class)]
#[CoversClass(EnrollmentAuthority::class)]
#[CoversClass(FactorRemoval::class)]
#[CoversClass(RequiredFactorPolicy::class)]
final class PasskeyChangeGateTest extends TestCase
{
    use ArrangesPasskeys;

    /**
     * Fake the gate's events and make recovery codes quick to hash.
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
     * Each of the gate's calls is refused outside a transaction.
     *
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
                fn () => $gate->registering($user, self::APPLICATION, $this->registration($user)),
                static function () use ($gate, $user): void {
                    $gate->removing($user, self::APPLICATION, self::CREDENTIAL);
                },
                static function () use ($gate, $user): void {
                    $gate->changing($user, self::APPLICATION, self::CREDENTIAL);
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
     * On an application that does not enable passkeys, and for an identity that
     * is not a person, the registration goes on as a sign-in passkey only:
     * nothing is associated.
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

        $result = DB::transaction(fn () => $this->gate()->registering($machine, self::APPLICATION, $this->registration($user, self::OTHER_CREDENTIAL)));

        self::assertNull($result);

        self::assertSame(0, Factor::query()->count());
        self::assertSame(0, PasskeyAssociation::query()->count());
        Event::assertNotDispatched(PasskeyAssociated::class);
    }

    /**
     * A first passkey on an active session needs the first factor proved again:
     * the default reauthenticator refuses, and the refusal rolls back the
     * caller's own credential with everything else.
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
     * With the first factor proved again, a first passkey is associated as a
     * confirmed factor enrolled through the application, with its recovery
     * codes, and reported once the caller commits.
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
     * Recovery codes come with the first passkey only when the application
     * accepts them and the session then meets the level it issues them at.
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
     * A stale reauthentication does not authorise the first passkey.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAStaleReauthenticationIsRefused(): void
    {
        $this->enablePasskeys();
        $this->reauthenticate(EnrollmentAuthority::REAUTHENTICATION_MAX_AGE + 1);

        $user = $this->signedInPerson();

        self::assertSame(FailureReason::NOT_FRESH, $this->refusal(fn () => $this->registrar()->register($user, self::APPLICATION, $this->registration($user))));
    }

    /**
     * A further passkey needs a fresh step-up, not a reauthentication.
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
     * A pending session may associate a passkey without a step-up only as its
     * bootstrap enrolment, when the application allows it and the identity has
     * no factor.
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
     * The application's limit on confirmed factors of a type is applied.
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
     * A credential associated already, with this identity or another, is
     * refused: a registration is never idempotent.
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
     * A registration bound to another session, or one that observed no user
     * presence, is refused; so is one made for another identity than the
     * request's caller.
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
     * A caller that fails after the gate allowed the registration leaves no
     * factor, association, recovery code or event behind.
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
     * Removing a credential associated with nobody is a no-op, whatever the
     * session's freshness.
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
     * Removing an associated passkey needs a fresh step-up.
     *
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
     * While another factor remains, a step-up made only with the passkey being
     * removed does not authorise its removal; one made with the other factor
     * does, and the recovery codes and the session, still meeting its
     * requirement, stay as they are.
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

        $this->container()->make(RecoveryCodeService::class)->generate($user);

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
        self::assertSame([], $transition->returned);
        Event::assertDispatched(FactorRemoved::class, static fn (FactorRemoved $event): bool => $event->factor->id === $passkey->id);
    }

    /**
     * A step-up made with the identity's only factor authorises removing it
     * when no factor is required, and the recovery codes go with it.
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

        $this->container()->make(RecoveryCodeService::class)->generate($user);
        $this->stepUpWith($user, $passkey);

        $this->registrar()->remove($user, self::APPLICATION, self::CREDENTIAL);

        self::assertSame(0, Factor::query()->count());
        self::assertSame(0, RecoveryCode::query()->count());
    }

    /**
     * The last acceptable factor is not removed while an application always
     * requires one, and the caller's own removal rolls back with it.
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
     * Removing a passkey stops the identity's other sessions counting, and the
     * current session keeps its proofs but the removed factor's.
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
        $other->record(SignInProofs::of($user)->inSession('other-sign-in')->totp());

        $this->stepUpWith($user, $passkey);
        $this->stepUpWith($user, $totp);

        $this->registrar()->remove($user, self::APPLICATION, self::CREDENTIAL);

        $kept = array_map(static fn (Proof $proof): ?string => $proof->reference, $this->container()->make(ProofStore::class)->proofs($user, self::APPLICATION));

        self::assertSame([], $other->proofs($user, self::APPLICATION));
        self::assertSame([$totp->id], $kept);
    }

    /**
     * A change to an associated credential is refused and rolls back the
     * caller's change; one to an unassociated credential is a no-op.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChangeToAnAssociatedCredentialIsRefused(): void
    {
        $this->enablePasskeys();

        $user = $this->signedInPerson();

        $this->confirmedFactor($user, 'passkey', self::CREDENTIAL);

        DB::table(StandInRegistrar::TABLE)->insert(['owner' => ProofOwner::of($user)->key, 'credential_id' => self::CREDENTIAL]);

        $refusal = $this->refusal(fn () => DB::transaction(function () use ($user): bool {
            DB::table(StandInRegistrar::TABLE)->update(['credential_id' => self::OTHER_CREDENTIAL]);
            $this->gate()->changing($user, self::APPLICATION, self::CREDENTIAL);

            return true;
        }));

        self::assertSame(FailureReason::CREDENTIAL_ASSOCIATED, $refusal);
        self::assertTrue(StandInRegistrar::stores($user, self::CREDENTIAL));

        DB::transaction(function () use ($user): void {
            $this->gate()->changing($user, self::APPLICATION, self::OTHER_CREDENTIAL);
        });

        self::assertSame(1, PasskeyAssociation::query()->count());
    }

    /**
     * A change or a removal of an associated credential named for another
     * identity or application than the request's caller is refused as not
     * found; one of a credential associated with nobody is a no-op whoever it
     * is named for.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChangeOrRemovalForAnotherThanTheCallerIsRefused(): void
    {
        $this->enablePasskeys();

        $user  = $this->signedInPerson();
        $other = TestUser::query()->create(['email' => 'other@example.test']);

        $this->confirmedFactor($user, 'passkey', self::CREDENTIAL);

        $calls = [
            fn () => $this->gate()->changing($other, self::APPLICATION, self::CREDENTIAL),
            fn () => $this->gate()->changing($user, 'another-application', self::CREDENTIAL),
            fn () => $this->gate()->removing($other, self::APPLICATION, self::CREDENTIAL),
            fn () => $this->gate()->removing($user, 'another-application', self::CREDENTIAL),
        ];

        foreach ($calls as $call) {
            self::assertSame(FailureReason::NOT_FOUND, $this->refusal(static fn () => DB::transaction($call)));
        }

        DB::transaction(function () use ($other): void {
            $this->gate()->changing($other, self::APPLICATION, self::OTHER_CREDENTIAL);
            $this->gate()->removing($other, self::APPLICATION, self::OTHER_CREDENTIAL);
        });

        self::assertSame(1, PasskeyAssociation::query()->count());
    }

    /**
     * The caller removing a credential associated with another identity is
     * refused as not found, and the other identity's factor and association
     * stay.
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
            $this->gate()->removing($user, self::APPLICATION, self::CREDENTIAL);
        })));
        self::assertTrue(Factor::query()->whereKey($passkey->id)->exists());
        self::assertSame($passkey->id, PasskeyAssociation::query()->sole()->factor_id);
    }

    /**
     * The passkey factor carries the label it was registered with.
     *
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
            $this->gate()->registering($user, self::APPLICATION, $this->registration($user), 'Work laptop');
        });

        self::assertSame('Work laptop', Factor::query()->sole()->label);
    }

    /**
     * A caller with no sign-in on the application has nothing to bind a
     * registration to, so it is refused as not found.
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
     * Registering, changing and removing in one outer transaction commit as one
     * change; a refusal anywhere in it rolls all of it back.
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
            $this->gate()->registering($user, self::APPLICATION, $this->registration($user));
            $this->gate()->changing($user, self::APPLICATION, self::OTHER_CREDENTIAL);
            $this->gate()->removing($user, self::APPLICATION, self::CREDENTIAL);
        });

        self::assertSame([$totp->id], Factor::query()->pluck('id')->all());
        self::assertSame(0, PasskeyAssociation::query()->count());
        Event::assertDispatched(PasskeyAssociated::class);
        Event::assertDispatched(FactorRemoved::class);

        $refusal = $this->refusal(fn () => DB::transaction(function () use ($user): bool {
            $this->gate()->registering($user, self::APPLICATION, $this->registration($user, self::OTHER_CREDENTIAL));
            $this->gate()->changing($user, self::APPLICATION, self::OTHER_CREDENTIAL);

            return true;
        }));

        self::assertSame(FailureReason::CREDENTIAL_ASSOCIATED, $refusal);
        self::assertSame([$totp->id], Factor::query()->pluck('id')->all());
        self::assertSame(0, PasskeyAssociation::query()->count());
    }

    /**
     * Bind a reauthenticator that proves the password again, the given number
     * of seconds ago.
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
     * Make every request carry a pending session of the user's, in its own
     * session, allowing the given actions.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @param  list<\SineMacula\Laravel\Mfa\Enums\PendingAction>  $actions
     * @return void
     */
    private function pending(TestUser $user, array $actions): void
    {
        $proofs = SignInProofs::of($user)->inSession('pending-1');

        $this->container()->instance(PendingSessionResolver::class, new FixedPendingSessionResolver(
            new PendingContext($user, self::APPLICATION, 'pending-1', $proofs->password(), Requirement::none()->withAdditionalVerification(), $actions),
        ));
    }

    /**
     * The reason the call was refused with.
     *
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
     * The stand-in authentication layer's registrar.
     *
     * @return \Tests\Fixtures\Passkeys\StandInRegistrar
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function registrar(): StandInRegistrar
    {
        return new StandInRegistrar($this->gate());
    }

    /**
     * The gate under test.
     *
     * @return \SineMacula\Laravel\Mfa\Passkeys\PasskeyChangeGate
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function gate(): PasskeyChangeGate
    {
        return $this->container()->make(PasskeyChangeGate::class);
    }
}
