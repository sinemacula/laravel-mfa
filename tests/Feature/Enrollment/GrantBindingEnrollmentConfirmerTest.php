<?php

declare(strict_types = 1);

namespace Tests\Feature\Enrollment;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Assurance\Combination;
use SineMacula\Laravel\Mfa\Assurance\DefaultCombinationPolicy;
use SineMacula\Laravel\Mfa\Assurance\Evaluation;
use SineMacula\Laravel\Mfa\Attempts\ChallengeCounters;
use SineMacula\Laravel\Mfa\Codes\PackageChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Drivers\EmailDriver;
use SineMacula\Laravel\Mfa\Drivers\SmsDriver;
use SineMacula\Laravel\Mfa\Drivers\TotpDriver;
use SineMacula\Laravel\Mfa\Drivers\TotpSettings;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentAuthority;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentConfirmation;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentConfirmer;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentGrant;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentRequest;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentService;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentSettings;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentStart;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentStarter;
use SineMacula\Laravel\Mfa\Enrollment\GrantAuthority;
use SineMacula\Laravel\Mfa\Enrollment\PendingEnrollments;
use SineMacula\Laravel\Mfa\Enums\EnrollmentAuthorization;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Exceptions\CodeNotSentException;
use SineMacula\Laravel\Mfa\Factors\FactorChannel;
use SineMacula\Laravel\Mfa\Factors\FactorLabel;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Models\Enrollment;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Proofs\ProofStoreCompletion;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeIssuance;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService;
use SineMacula\Laravel\Mfa\Requirements\ConfiguredFreshnessGate;
use SineMacula\Laravel\Mfa\Requirements\ReenrollmentObligation;
use SineMacula\Laravel\Mfa\Requirements\RequirementService;
use SineMacula\Laravel\Mfa\Requirements\SessionReevaluation;
use SineMacula\Laravel\Mfa\Secrets\RevealedSecret;
use SineMacula\Laravel\Mfa\Verification\ProofAcceptance;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Context\FixedPendingSessionResolver;
use Tests\Fixtures\Enrollment\Concerns\ArrangesEnrollment;
use Tests\Fixtures\Exceptions\InvalidPendingCredentialException;
use Tests\Fixtures\Seams\InterruptingProofStore;
use Tests\TestCase;

/**
 * A grant confirms only in the session that started it, for the identity and
 * the application it was started for, on the kind of session its authority
 * serves. Every mismatch answers `not_found`, and the row keeps no secret.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EnrollmentService::class)]
#[CoversClass(EnrollmentStarter::class)]
#[CoversClass(EnrollmentConfirmer::class)]
#[CoversClass(PendingEnrollments::class)]
#[CoversClass(EnrollmentAuthority::class)]
#[CoversClass(GrantAuthority::class)]
#[CoversClass(EnrollmentGrant::class)]
#[CoversClass(EnrollmentRequest::class)]
#[CoversClass(EnrollmentStart::class)]
#[CoversClass(EnrollmentConfirmation::class)]
#[CoversClass(EnrollmentSettings::class)]
#[CoversClass(FactorChannel::class)]
#[CoversClass(FactorLabel::class)]
#[CoversClass(ChallengeCounters::class)]
#[CoversClass(PackageChallengeGateway::class)]
#[CoversClass(CodeNotSentException::class)]
#[CoversClass(ProofAcceptance::class)]
#[CoversClass(ProofStoreCompletion::class)]
#[CoversClass(RecoveryCodeIssuance::class)]
#[CoversClass(RecoveryCodeService::class)]
#[CoversClass(ReenrollmentObligation::class)]
#[CoversClass(SessionReevaluation::class)]
#[CoversClass(ConfiguredFreshnessGate::class)]
#[CoversClass(RequirementService::class)]
#[CoversClass(TotpDriver::class)]
#[CoversClass(TotpSettings::class)]
#[CoversClass(EmailDriver::class)]
#[CoversClass(SmsDriver::class)]
#[CoversClass(MfaManager::class)]
#[CoversClass(Evaluation::class)]
#[CoversClass(Combination::class)]
#[CoversClass(DefaultCombinationPolicy::class)]
final class GrantBindingEnrollmentConfirmerTest extends TestCase
{
    use ArrangesEnrollment;

    /**
     * Arrange the application.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeVerification();
    }

    /**
     * Rows of what a stored enrolment is changed to, so it is no longer bound
     * to who is asking.
     *
     * @return iterable<string, array{array<string, string>}>
     */
    public static function otherBindings(): iterable
    {
        yield 'another identity' => [['authenticatable_id' => '999']];
        yield 'another type of identity' => [['authenticatable_type' => 'other']];
        yield 'another application' => [['application' => 'admin']];
        yield 'another session' => [['session_id' => 'another-digest']];
        yield 'another authority' => [['authority' => 'bootstrap']];
    }

    /**
     * A grant bound to anything else answers `not_found`, counting nothing.
     *
     * @param  array<string, string>  $change
     * @return void
     */
    #[DataProvider('otherBindings')]
    public function testAGrantBoundElsewhereIsNotFound(array $change): void
    {
        $this->reauthenticatedPerson();

        $start = $this->startedTotp();

        Enrollment::query()->update($change);
        $this->forgetReports();

        $confirmation = $this->mfa()->confirmEnrollment(Callers::current(), $this->grantOf($start), $this->appCode($start));

        self::assertSame(FailureReason::NOT_FOUND, $confirmation->reason);
        self::assertNull($this->failureReported()->factor);
        self::assertNull($this->failureReported()->type);
        self::assertSame(0, $this->rowOf($start)->attempts);
        self::assertFalse($this->pendingFactorOf($start)->isConfirmed());
    }

    /**
     * An owner differing only in case is not the owner, wherever the database's
     * collation would find them equal.
     *
     * @return void
     */
    public function testAnOwnerDifferingInCaseIsNotTheOwner(): void
    {
        $user  = $this->reauthenticatedPerson();
        $start = $this->startedTotp();

        Enrollment::query()->update(['authenticatable_type' => strtoupper(ProofOwner::of($user)->type)]);

        self::assertSame(FailureReason::NOT_FOUND, $this->mfa()->confirmEnrollment(Callers::current(), $this->grantOf($start), $this->appCode($start))->reason);
    }

    /**
     * An unknown grant is not found, and so is the right grant once used, which
     * returns none of the secrets again.
     *
     * @return void
     */
    public function testAnUnknownGrantAndAUsedOneAreNotFound(): void
    {
        $this->reauthenticatedPerson();

        $start = $this->startedTotp();
        $code  = $this->appCode($start);

        self::assertSame(FailureReason::NOT_FOUND, $this->mfa()->confirmEnrollment(Callers::current(), 'unknown', $code)->reason);
        self::assertTrue($this->mfa()->confirmEnrollment(Callers::current(), $this->grantOf($start), $code)->isConfirmed());

        $second = $this->mfa()->confirmEnrollment(Callers::current(), $this->grantOf($start), $code);

        self::assertSame(FailureReason::NOT_FOUND, $second->reason);
        self::assertSame([], $second->recoveryCodes);
        self::assertSame(0, Enrollment::query()->count());
    }

    /**
     * A grant whose pending factor is gone is not found.
     *
     * @return void
     */
    public function testAGrantWhoseFactorIsGoneIsNotFound(): void
    {
        $this->reauthenticatedPerson();

        $start = $this->startedTotp();
        $code  = $this->appCode($start);

        Factor::query()->delete();

        self::assertSame(FailureReason::NOT_FOUND, $this->mfa()->confirmEnrollment(Callers::current(), $this->grantOf($start), $code)->reason);
    }

    /**
     * The grant may be passed as the secret it was returned as, or as what was
     * revealed from it.
     *
     * @return void
     */
    public function testTheGrantMayBeGivenAsASecretOrAsAString(): void
    {
        $this->reauthenticatedPerson();

        $start = $this->startedTotp();

        self::assertInstanceOf(RevealedSecret::class, $start->grant);
        self::assertTrue($this->mfa()->confirmEnrollment(Callers::current(), $start->grant, $this->appCode($start))->isConfirmed());
    }

    /**
     * A bootstrap grant is refused on an active session, and an active grant on
     * a pending one.
     *
     * @return void
     */
    public function testAGrantServesOnlyTheKindOfSessionItsAuthorityDoes(): void
    {
        $user  = $this->bootstrapPerson();
        $start = $this->startedTotp();

        $this->noPendingSession();
        $this->actingAs($user);

        self::assertSame(EnrollmentAuthorization::BOOTSTRAP, $this->rowOf($start)->authority);
        self::assertSame(FailureReason::NOT_FOUND, $this->mfa()->confirmEnrollment(Callers::current(), $this->grantOf($start), $this->appCode($start))->reason);

        Enrollment::query()->update(['authority' => EnrollmentAuthorization::STEP_UP]);

        $this->pendingSession($user, null, self::BOOTSTRAP_ACTIONS);

        self::assertSame(FailureReason::NOT_FOUND, $this->mfa()->confirmEnrollment(Callers::current(), $this->grantOf($start), $this->appCode($start))->reason);
    }

    /**
     * An advanced verification generation kills the grant, as `expired`.
     *
     * @return void
     */
    public function testAnAdvancedGenerationKillsTheGrant(): void
    {
        $user  = $this->reauthenticatedPerson();
        $start = $this->startedTotp();
        $code  = $this->appCode($start);

        VerificationGeneration::advance($user);

        self::assertSame(FailureReason::EXPIRED, $this->mfa()->confirmEnrollment(Callers::current(), $this->grantOf($start), $code)->reason);
        self::assertSame(0, Enrollment::query()->count());
        self::assertSame(0, Factor::query()->count());
    }

    /**
     * A sign-in that changes between capture and lock counts nothing and
     * reports nothing.
     *
     * @return void
     */
    public function testASignInChangedBeforeTheLockCountsNothing(): void
    {
        $this->reauthenticatedPerson();

        $start = $this->startedTotp();
        $code  = $this->appCode($start);

        $this->forgetReports();

        $this->container()->instance(ProofStore::class, new InterruptingProofStore($this->container()->make(ProofStore::class)));

        self::assertSame(FailureReason::NOT_FOUND, $this->mfa()->confirmEnrollment(Callers::current(), $this->grantOf($start), $code)->reason);
        self::assertSame([], $this->reported);
        self::assertSame(0, $this->rowOf($start)->attempts);
        self::assertSame(0, $this->addressHits('127.0.0.1'));
    }

    /**
     * A request that serves nobody, a person with no sign-in, and a pending
     * credential that does not allow confirming, are all answered `not_found`
     * and reported to nobody.
     *
     * @return void
     */
    public function testARequestServingNobodyIsNotFound(): void
    {
        self::assertSame(FailureReason::NOT_FOUND, $this->mfa()->confirmEnrollment(Callers::current(), 'any', '000000')->reason);

        $user = $this->person();

        $this->actingAs($user);

        self::assertSame(FailureReason::NOT_FOUND, $this->mfa()->confirmEnrollment(Callers::current(), 'any', '000000')->reason);

        $this->pendingSession($user, null, [PendingAction::START_BOOTSTRAP_ENROLLMENT]);

        self::assertSame(FailureReason::NOT_FOUND, $this->mfa()->confirmEnrollment(Callers::current(), 'any', '000000')->reason);
        self::assertSame([], $this->reported);
    }

    /**
     * A credential that does not validate still throws through the resolver,
     * which is not the same as serving nobody.
     *
     * @return void
     */
    public function testACredentialThatDoesNotValidateThrows(): void
    {
        $this->container()->instance(PendingSessionResolver::class, new FixedPendingSessionResolver(invalid: true));

        $this->expectException(InvalidPendingCredentialException::class);

        $this->mfa()->confirmEnrollment(Callers::current(), 'any', '000000');
    }

    /**
     * The row holds a hash of the grant and a keyed digest of the sign-in,
     * never either itself.
     *
     * @return void
     */
    public function testTheRowHoldsNoSecret(): void
    {
        $user  = $this->reauthenticatedPerson();
        $start = $this->startedTotp();
        $row   = $this->rowOf($start);
        $grant = $this->grantOf($start);

        self::assertSame(64, strlen($grant));
        self::assertSame(hash('sha256', $grant), $row->grant_hash);
        self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $row->session_id);
        self::assertStringNotContainsString(self::SESSION, $row->session_id);
        self::assertSame(self::APPLICATION, $row->application);
        self::assertSame(VerificationGeneration::current($user), $row->generation);
        self::assertSame(EnrollmentAuthorization::REAUTHENTICATION, $row->authority);
        self::assertNull($row->challenge_id);
        self::assertArrayNotHasKey('grant_hash', $row->toArray());
        self::assertArrayNotHasKey('session_id', $row->toArray());
    }
}
