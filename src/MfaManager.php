<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa;

use Illuminate\Container\Container;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Container\Container as ContainerContract;
use Illuminate\Support\Manager;
use SineMacula\Laravel\Mfa\Codes\SendResult;
use SineMacula\Laravel\Mfa\Context\AuthenticationContextContributor;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Context\CallerContextResolver;
use SineMacula\Laravel\Mfa\Context\ClientContext;
use SineMacula\Laravel\Mfa\Context\SessionFirstFactor;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentConfirmation;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentRequest;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentService;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentStart;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Events\Actor;
use SineMacula\Laravel\Mfa\Exceptions\InsufficientAuthenticationException;
use SineMacula\Laravel\Mfa\Factors\FactorChange;
use SineMacula\Laravel\Mfa\Factors\FactorService;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use SineMacula\Laravel\Mfa\Lifecycle\FactorRemovalResult;
use SineMacula\Laravel\Mfa\Lifecycle\ForgetIdentity;
use SineMacula\Laravel\Mfa\Lifecycle\IdentityReset;
use SineMacula\Laravel\Mfa\Lifecycle\LifecycleService;
use SineMacula\Laravel\Mfa\Lifecycle\PruneResult;
use SineMacula\Laravel\Mfa\Lifecycle\RecordPruner;
use SineMacula\Laravel\Mfa\Passkeys\AssertionRequest;
use SineMacula\Laravel\Mfa\Proofs\ProofService;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeGeneration;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeIssuance;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeStatus;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Requirements\RequirementService;
use SineMacula\Laravel\Mfa\Requirements\StepUpRefusal;
use SineMacula\Laravel\Mfa\Secrets\RevealedSecret;
use SineMacula\Laravel\Mfa\Verification\ChallengeRequests;
use SineMacula\Laravel\Mfa\Verification\FactorOffers;
use SineMacula\Laravel\Mfa\Verification\Submission;
use SineMacula\Laravel\Mfa\Verification\VerificationResult;
use SineMacula\Laravel\Mfa\Verification\VerificationService;

/**
 * The factor driver registry and the package's single entry point; each other
 * method delegates to its capability's service.
 *
 * One instance may outlive many requests, so it keeps nothing: it resolves from
 * `Container::getInstance()` and builds drivers on every call.
 *
 * The method count is the facade's whole surface.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @inheritable
 *
 * @SuppressWarnings("php:S1448")
 */
class MfaManager extends Manager // phpcs:ignore SineMacula.Metrics.MaxMethodCount.TooManyMethods
{
    // phpcs:disable Squiz.Commenting.FunctionComment.ScalarTypeHintMissing

    /**
     * Laravel's manager would forward it to the default driver, outside
     * attempts, proofs and events. The arguments may hold a secret.
     *
     * @param  string  $method
     * @param  array<int|string, mixed>  $parameters
     * @return never
     *
     * @throws \BadMethodCallException
     */
    #[\Override]
    public function __call($method, $parameters): never
    {
        throw new \BadMethodCallException(sprintf('Method %s::%s() does not exist.', static::class, $method));
    }

    // phpcs:enable Squiz.Commenting.FunctionComment.ScalarTypeHintMissing

    /**
     * @return string
     */
    #[\Override]
    public function getDefaultDriver(): string
    {
        return 'totp';
    }

    /**
     * Built on every call, so a driver never keeps an earlier request's
     * configuration or sender.
     *
     * @param  string|\UnitEnum|null  $driver
     * @return \SineMacula\Laravel\Mfa\Contracts\FactorDriver
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function driver($driver = null): mixed
    {
        $name = match (true) {
            $driver instanceof \BackedEnum => (string) $driver->value,
            $driver instanceof \UnitEnum   => $driver->name,
            default                        => $driver,
        };

        /** @var \SineMacula\Laravel\Mfa\Contracts\FactorDriver */
        return $this->createDriver($name ?: $this->getDefaultDriver());
    }

    /**
     * The inherited setter would keep a request's application.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @return never
     *
     * @throws \LogicException
     */
    #[\Override]
    public function setContainer(ContainerContract $container): never
    {
        throw new \LogicException('The MFA manager resolves from the current application, and holds no container of a request\'s.');
    }

    /**
     * What the current sign-in must meet; empty when nothing further is needed.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @return \SineMacula\Laravel\Mfa\Requirements\Requirement
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    public function requirement(CallerContext $caller): Requirement
    {
        return $this->service(RequirementService::class)->requirement($caller);
    }

    /**
     * The stricter of the configured and the given requirement applies; an
     * operation with neither is never fresh.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  string  $operation
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    public function isFresh(CallerContext $caller, string $operation, ?Requirement $requirement = null): bool
    {
        return $this->service(RequirementService::class)->isFresh($caller, $operation, $requirement);
    }

    /**
     * The refusal the route gate raises, returned rather than thrown. Nothing
     * is added to the requirement, so compose it first.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @param  ?string  $operation
     * @return \SineMacula\Laravel\Mfa\Exceptions\InsufficientAuthenticationException
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\InvalidModelException
     */
    public function stepUpRefusal(CallerContext $caller, Requirement $requirement, ?string $operation = null): InsufficientAuthenticationException
    {
        return $this->service(StepUpRefusal::class)->of($caller, $requirement, $operation);
    }

    /**
     * The current sign-in's proofs that still count, oldest first; none on a
     * pending session.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @return list<\SineMacula\Laravel\Mfa\Proofs\Proof>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function proofs(CallerContext $caller): array
    {
        return $this->service(ProofService::class)->proofs($caller);
    }

    /**
     * Every factor, pending and other applications' included, preferred first.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @return list<\SineMacula\Laravel\Mfa\Factors\FactorSummary>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function factors(CallerContext $caller): array
    {
        return $this->service(FactorService::class)->factors($caller);
    }

    /**
     * Null for an id that is not one of the caller's factors.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  mixed  $factorId
     * @return ?\SineMacula\Laravel\Mfa\Factors\FactorSummary
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function factor(CallerContext $caller, mixed $factorId): ?FactorSummary
    {
        return $this->service(FactorService::class)->factor($caller, $factorId);
    }

    /**
     * Confirmed factors of an enabled type, accepted after the session's first
     * factor, preferred first.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @return list<\SineMacula\Laravel\Mfa\Factors\FactorSummary>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    public function offeredFactors(CallerContext $caller): array
    {
        return $this->service(FactorOffers::class)->offered($caller);
    }

    /**
     * The purpose defaults to sign-in on a pending session and step-up on an
     * active one. Verify under the same purpose.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  mixed  $factorId
     * @param  ?\SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @return \SineMacula\Laravel\Mfa\Codes\SendResult
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Throwable
     */
    public function sendCode(CallerContext $caller, mixed $factorId, ?Purpose $purpose = null): SendResult
    {
        return $this->service(ChallengeRequests::class)->sendCode($caller, $factorId, $purpose);
    }

    /**
     * Start a passkey assertion request, or say why not.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  mixed  $factorId
     * @param  ?\SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @return \SineMacula\Laravel\Mfa\Passkeys\AssertionRequest
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Throwable
     */
    public function requestAssertion(CallerContext $caller, mixed $factorId, ?Purpose $purpose = null): AssertionRequest
    {
        return $this->service(ChallengeRequests::class)->requestAssertion($caller, $factorId, $purpose);
    }

    /**
     * The purpose defaults to sign-in on a pending session and step-up on an
     * active one.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  \SineMacula\Laravel\Mfa\Verification\Submission  $submission
     * @param  ?\SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @return \SineMacula\Laravel\Mfa\Verification\VerificationResult
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Throwable
     */
    public function verify(CallerContext $caller, #[\SensitiveParameter] Submission $submission, ?Purpose $purpose = null): VerificationResult
    {
        return $this->service(VerificationService::class)->verify($caller, $submission, $purpose);
    }

    /**
     * A pending factor and the grant that may confirm it, or why it may not
     * start.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  \SineMacula\Laravel\Mfa\Enrollment\EnrollmentRequest  $request
     * @return \SineMacula\Laravel\Mfa\Enrollment\EnrollmentStart
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Throwable
     */
    public function startEnrollment(CallerContext $caller, #[\SensitiveParameter] EnrollmentRequest $request): EnrollmentStart
    {
        return $this->service(EnrollmentService::class)->start($caller, $request);
    }

    /**
     * Confirm with the first valid code, in the session that started it.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  \SineMacula\Laravel\Mfa\Secrets\RevealedSecret|string  $grant
     * @param  string  $code
     * @return \SineMacula\Laravel\Mfa\Enrollment\EnrollmentConfirmation
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Throwable
     */
    public function confirmEnrollment(CallerContext $caller, #[\SensitiveParameter] RevealedSecret|string $grant, #[\SensitiveParameter] string $code): EnrollmentConfirmation
    {
        return $this->service(EnrollmentService::class)->confirm($caller, $grant, $code);
    }

    /**
     * Renews nothing.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  \SineMacula\Laravel\Mfa\Secrets\RevealedSecret|string  $grant
     * @return \SineMacula\Laravel\Mfa\Codes\SendResult
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Throwable
     */
    public function resendEnrollmentCode(CallerContext $caller, #[\SensitiveParameter] RevealedSecret|string $grant): SendResult
    {
        return $this->service(EnrollmentService::class)->resend($caller, $grant);
    }

    /**
     * False for a grant that is not the caller's.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  \SineMacula\Laravel\Mfa\Secrets\RevealedSecret|string  $grant
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Throwable
     *
     * @imperative
     */
    public function cancelEnrollment(CallerContext $caller, #[\SensitiveParameter] RevealedSecret|string $grant): bool
    {
        return $this->service(EnrollmentService::class)->cancel($caller, $grant);
    }

    /**
     * No step-up needed; a blank label clears it.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  mixed  $factorId
     * @param  ?string  $label
     * @return \SineMacula\Laravel\Mfa\Factors\FactorChange
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    public function renameFactor(CallerContext $caller, mixed $factorId, ?string $label): FactorChange
    {
        return $this->service(FactorService::class)->rename($caller, $factorId, $label);
    }

    /**
     * No step-up needed.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  mixed  $factorId
     * @return \SineMacula\Laravel\Mfa\Factors\FactorChange
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Throwable
     */
    public function setPreferredFactor(CallerContext $caller, mixed $factorId): FactorChange
    {
        return $this->service(FactorService::class)->setPreferred($caller, $factorId);
    }

    /**
     * Needs a fresh step-up.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  mixed  $factorId
     * @return \SineMacula\Laravel\Mfa\Lifecycle\FactorRemovalResult
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Throwable
     */
    public function removeFactor(CallerContext $caller, mixed $factorId): FactorRemovalResult
    {
        return $this->service(LifecycleService::class)->removeFactor($caller, $factorId);
    }

    /**
     * Remove everything the identity holds. Who may reset whom is the
     * application's to authorise.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Events\Actor  $actor
     * @param  string  $reason
     * @param  bool  $requireReenrollment
     * @param  ?\SineMacula\Laravel\Mfa\Context\ClientContext  $client
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    public function resetIdentity(MultiFactorAuthenticatable $identity, Actor $actor, string $reason, bool $requireReenrollment = true, ?ClientContext $client = null): void
    {
        $this->service(IdentityReset::class)->reset($identity, $actor, $reason, $requireReenrollment, $client);
    }

    /**
     * Whether a live lockout was lifted. Failures in a row and a disabled state
     * stay.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  mixed  $factorId
     * @param  \SineMacula\Laravel\Mfa\Events\Actor  $actor
     * @param  ?\SineMacula\Laravel\Mfa\Context\ClientContext  $client
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Throwable
     *
     * @imperative
     */
    public function unlockFactor(MultiFactorAuthenticatable $identity, mixed $factorId, Actor $actor, ?ClientContext $client = null): bool
    {
        return $this->service(LifecycleService::class)->unlockFactor($identity, $factorId, $actor, $client);
    }

    /**
     * Whether a disabled factor was enabled. Its failures and any lockout stay,
     * so its next failure disables it again.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  mixed  $factorId
     * @param  \SineMacula\Laravel\Mfa\Events\Actor  $actor
     * @param  ?\SineMacula\Laravel\Mfa\Context\ClientContext  $client
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Throwable
     *
     * @imperative
     */
    public function enableFactor(MultiFactorAuthenticatable $identity, mixed $factorId, Actor $actor, ?ClientContext $client = null): bool
    {
        return $this->service(LifecycleService::class)->enableFactor($identity, $factorId, $actor, $client);
    }

    /**
     * Whether a live lockout was lifted. Failures in a row stay.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Events\Actor  $actor
     * @param  ?\SineMacula\Laravel\Mfa\Context\ClientContext  $client
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Throwable
     *
     * @imperative
     */
    public function unlockIdentity(MultiFactorAuthenticatable $identity, Actor $actor, ?ClientContext $client = null): bool
    {
        return $this->service(LifecycleService::class)->unlockIdentity($identity, $actor, $client);
    }

    /**
     * Delete everything held for a deleted identity. `HasFactors` calls it for
     * an Eloquent identity.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $identity
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Throwable
     */
    public function forgetIdentity(Authenticatable $identity): void
    {
        $this->service(ForgetIdentity::class)->forget($identity);
    }

    /**
     * Delete stale records, counting each kind.
     *
     * @return \SineMacula\Laravel\Mfa\Lifecycle\PruneResult
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \Throwable
     *
     * @imperative
     */
    public function prune(): PruneResult
    {
        return ($this->service(RecordPruner::class))();
    }

    /**
     * Replace the recovery code set, returning the codes once, or refuse and
     * keep the earlier set.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @return \SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeGeneration
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Throwable
     */
    public function generateRecoveryCodes(CallerContext $caller): RecoveryCodeGeneration
    {
        return $this->service(RecoveryCodeIssuance::class)->generate($caller);
    }

    /**
     * Never includes a code.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @return ?\SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeStatus
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\InvalidModelException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    public function recoveryCodeStatus(CallerContext $caller): ?RecoveryCodeStatus
    {
        return $this->service(RecoveryCodeService::class)->statusOfCaller($caller);
    }

    /**
     * The `mfa` namespace of the caller's authentication context; neutral on a
     * pending session.
     *
     * @formatter:off
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @return array{
     *     accepted: bool,
     *     multifactor: bool,
     *     factor_types: list<string>,
     *     level: string,
     *     phishing_resistant: bool,
     *     user_verification: bool,
     *     last_verification_age_seconds: ?int,
     *     has_confirmed_factor: bool,
     * }
     *
     * @formatter:on
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    public function authenticationContext(CallerContext $caller): array
    {
        $served = $this->service(CallerContextResolver::class)->resolve($caller, null);

        if ($served === null) {
            return AuthenticationContextContributor::neutral();
        }

        $session = $this->service(ProofStore::class)->currentSession($served->identity, $served->application);
        $proofs  = $session === null ? [] : $this->service(SessionFirstFactor::class)->proofsOf($served->identity, $served->application, $session);

        return $this->service(AuthenticationContextContributor::class)->contributeFor($served->identity, $served->application, $session ?? '', ...$proofs);
    }

    /**
     * For an identity's `morphMany(Mfa::factorModel(), 'authenticatable')`.
     *
     * @return class-string<\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\InvalidModelException
     */
    public function factorModel(): string
    {
        return $this->service(FactorService::class)->factorModel();
    }

    // phpcs:disable Squiz.Commenting.FunctionComment.ScalarTypeHintMissing

    /**
     * Passes the current application, not the one the manager was built with.
     *
     * @param  string  $driver
     * @return mixed
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    protected function callCustomCreator($driver): mixed
    {
        return $this->customCreators[$driver](Container::getInstance());
    }

    // phpcs:enable Squiz.Commenting.FunctionComment.ScalarTypeHintMissing

    /**
     * @template TService of object
     *
     * @param  class-string<TService>  $service
     * @return TService
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function service(string $service): object
    {
        return Container::getInstance()->make($service);
    }
}
