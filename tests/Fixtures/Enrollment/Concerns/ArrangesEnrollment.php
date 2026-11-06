<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Enrollment\Concerns;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Mfa\Assurance\Channel;
use SineMacula\Laravel\Mfa\Assurance\ObservedProperties;
use SineMacula\Laravel\Mfa\Contracts\MfaEvent;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Contracts\Reauthenticator;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentRequest;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentStart;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Models\Enrollment;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Models\IdentityState;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Requirements\SignInProofs;
use Tests\Fixtures\Seams\FreshReauthenticator;
use Tests\Fixtures\Verification\Concerns\ArrangesVerification;

/**
 * Arranges the enrolment tests over the verification ones: the `web`
 * application with TOTP and email enabled; a person enrolling their first
 * factor by proving the first one again, one with a factor and a recent
 * step-up, or one on a bootstrap session; and an enrolment under way.
 *
 * @phpstan-require-extends \Tests\TestCase
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait ArrangesEnrollment
{
    use ArrangesVerification;

    /** @var string The account name an authenticator app shows. */
    protected const string ACCOUNT = 'person@example.test';

    /** @var list<\SineMacula\Laravel\Mfa\Enums\PendingAction> What a pending credential allows on the bootstrap path. */
    protected const array BOOTSTRAP_ACTIONS = [PendingAction::START_BOOTSTRAP_ENROLLMENT, PendingAction::CONFIRM_BOOTSTRAP_ENROLLMENT];

    /**
     * A signed-in person with a first factor, who has just proved it again, so
     * they may enrol their first additional factor.
     *
     * @param  int  $secondsAgo
     * @return \Tests\Fixtures\Identities\TestUser
     */
    protected function reauthenticatedPerson(int $secondsAgo = 0): TestUser
    {
        $user = $this->signedInPerson();

        $this->recordFirstFactor($user);
        $this->container()->instance(Reauthenticator::class, new FreshReauthenticator($this->container()->make(ProofStore::class), $secondsAgo));

        return $user;
    }

    /**
     * A signed-in person with a confirmed factor and a step-up with it the
     * given number of seconds ago.
     *
     * @param  int  $secondsAgo
     * @param  array<string, mixed>  $attributes
     * @return \Tests\Fixtures\Identities\TestUser
     */
    protected function steppedUpPerson(int $secondsAgo = 0, array $attributes = []): TestUser
    {
        $user = $this->signedInPerson();

        $this->container()->make(ProofStore::class)->record(SignInProofs::of($user)->inSession(self::SESSION)->password($secondsAgo + 60));

        $this->recordStepUp($user, $this->totpFactor($user, ['application' => self::APPLICATION, ...$attributes]), $secondsAgo);

        return $user;
    }

    /**
     * Record a step-up the person made with the factor.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @param  \SineMacula\Laravel\Mfa\Models\Factor  $factor
     * @param  int  $secondsAgo
     * @return void
     */
    protected function recordStepUp(TestUser $user, Factor $factor, int $secondsAgo = 0): void
    {
        $owner = ProofOwner::of($user);

        $this->container()->make(ProofStore::class)->record(new Proof(
            kind      : ProofKind::ADDITIONAL_FACTOR,
            method    : 'totp',
            channel   : new Channel(ChannelKind::AUTHENTICATOR_APP, $factor->id),
            reference : $factor->id,
            properties: ObservedProperties::none(),
            provedAt  : CarbonImmutable::now()->subSeconds($secondsAgo),
            binding   : new ProofBinding($owner->type, $owner->key, self::APPLICATION, self::SESSION, Purpose::STEP_UP),
            generation: VerificationGeneration::current($user),
        ));
    }

    /**
     * A person on a pending session the store knows of, on an application that
     * allows bootstrap for TOTP and email, whose pending session expires in the
     * given number of minutes.
     *
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @param  list<\SineMacula\Laravel\Mfa\Enums\PendingAction>  $actions
     * @param  int  $minutes
     * @return \Tests\Fixtures\Identities\TestUser
     */
    protected function bootstrapPerson(?Requirement $requirement = null, array $actions = self::BOOTSTRAP_ACTIONS, int $minutes = 10): TestUser
    {
        $this->enableApplication(['bootstrap' => ['enabled' => true, 'types' => ['totp', 'email']]]);

        $user = $this->person();

        $this->beginSignIn($user, self::PENDING);
        $this->pendingSession($user, $requirement, $actions, expiresAt: CarbonImmutable::now()->addMinutes($minutes));

        return $user;
    }

    /**
     * A first factor proved by a code sent to the address given, on the
     * session.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @param  string  $session
     * @param  string  $address
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     */
    protected function emailFirstFactor(TestUser $user, string $session, string $address = self::ADDRESS): Proof
    {
        $owner = ProofOwner::of($user);

        return new Proof(
            kind      : ProofKind::FIRST_FACTOR,
            method    : 'email',
            channel   : new Channel(ChannelKind::EMAIL, $address),
            reference : null,
            properties: ObservedProperties::none(),
            provedAt  : CarbonImmutable::now()->subMinute(),
            binding   : new ProofBinding($owner->type, $owner->key, self::APPLICATION, $session, Purpose::SIGN_IN),
            generation: VerificationGeneration::current($user),
        );
    }

    /**
     * Start a TOTP enrolment, which must start.
     *
     * @return \SineMacula\Laravel\Mfa\Enrollment\EnrollmentStart
     */
    protected function startedTotp(): EnrollmentStart
    {
        return $this->started(EnrollmentRequest::totp(self::ACCOUNT));
    }

    /**
     * Start an email enrolment, which must start.
     *
     * @param  string  $address
     * @return \SineMacula\Laravel\Mfa\Enrollment\EnrollmentStart
     */
    protected function startedEmail(string $address = self::ADDRESS): EnrollmentStart
    {
        return $this->started(EnrollmentRequest::delivered('email', $address));
    }

    /**
     * Start the enrolment, which must start.
     *
     * @param  \SineMacula\Laravel\Mfa\Enrollment\EnrollmentRequest  $request
     * @return \SineMacula\Laravel\Mfa\Enrollment\EnrollmentStart
     */
    protected function started(EnrollmentRequest $request): EnrollmentStart
    {
        $start = $this->mfa()->startEnrollment(Callers::current(), $request);

        Assert::assertTrue($start->hasStarted(), sprintf('The enrolment must start, not [%s].', $start->reason?->value));

        return $start;
    }

    /**
     * The grant of an enrolment that started.
     *
     * @param  \SineMacula\Laravel\Mfa\Enrollment\EnrollmentStart  $start
     * @return string
     */
    protected function grantOf(EnrollmentStart $start): string
    {
        Assert::assertNotNull($start->grant);

        return $start->grant->reveal();
    }

    /**
     * The pending factor of an enrolment that started, as stored.
     *
     * @param  \SineMacula\Laravel\Mfa\Enrollment\EnrollmentStart  $start
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    protected function pendingFactorOf(EnrollmentStart $start): Factor
    {
        return Factor::query()->whereKey($start->factor?->id)->sole();
    }

    /**
     * The row of an enrolment that started.
     *
     * @param  \SineMacula\Laravel\Mfa\Enrollment\EnrollmentStart  $start
     * @return \SineMacula\Laravel\Mfa\Models\Enrollment
     */
    protected function rowOf(EnrollmentStart $start): Enrollment
    {
        return Enrollment::query()->where('factor_id', $start->factor?->id)->sole();
    }

    /**
     * The code an authenticator app shows for a TOTP enrolment that started,
     * read from the secret returned.
     *
     * @param  \SineMacula\Laravel\Mfa\Enrollment\EnrollmentStart  $start
     * @param  int  $steps
     * @return string
     */
    protected function appCode(EnrollmentStart $start, int $steps = 0): string
    {
        return AuthenticatorApp::code($this->pendingFactorOf($start), $steps);
    }

    /**
     * A code the app does not show now.
     *
     * @param  \SineMacula\Laravel\Mfa\Enrollment\EnrollmentStart  $start
     * @return string
     */
    protected function wrongCode(EnrollmentStart $start): string
    {
        return $this->appCode($start, 5);
    }

    /**
     * The short names of what was reported, oldest first.
     *
     * @return list<string>
     */
    protected function reportedNames(): array
    {
        return array_map(static fn (MfaEvent $event): string => class_basename($event), $this->reported);
    }

    /**
     * Set the identity's obligation to enrol again.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @return void
     */
    protected function obligeToEnroll(TestUser $user): void
    {
        $owner = ProofOwner::of($user);

        IdentityState::query()->updateOrCreate(
            ['authenticatable_type' => $owner->type, 'authenticatable_id' => $owner->key],
            ['reenrollment_required' => true],
        );
    }
}
