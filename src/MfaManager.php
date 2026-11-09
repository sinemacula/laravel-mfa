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
 * MFA manager.
 *
 * The factor driver registry (Laravel's `Manager`, so `Mfa::extend()` works as
 * for any manager) and the package's single entry point. Every other method is
 * a one-line delegation to the service of the capability it belongs to,
 * resolved from the application current at the time on each call:
 *
 * - `Requirements\RequirementService`: what the current sign-in must prove
 *   (`requirement()`) and whether it is fresh enough for an operation
 *   (`isFresh()`).
 * - `Factors\FactorService`: the identity's factors and the factor model,
 *   `factors()`, `factor()`, `renameFactor()` and `setPreferredFactor()`.
 * - `Proofs\ProofService`: the proofs the current sign-in has recorded
 *   (`proofs()`).
 * - `Verification\VerificationService`: `verify()`.
 * - `Verification\ChallengeRequests`: `sendCode()` and `requestAssertion()`.
 * - `Verification\FactorOffers`: `offeredFactors()`.
 * - `Enrollment\EnrollmentService`: `startEnrollment()`, `confirmEnrollment()`,
 *   `resendEnrollmentCode()` and `cancelEnrollment()`.
 * - `Lifecycle\LifecycleService`: `removeFactor()`, `unlockFactor()` and
 *   `unlockIdentity()`.
 * - `Lifecycle\IdentityReset`: `resetIdentity()`.
 * - `Lifecycle\ForgetIdentity`: `forgetIdentity()`.
 * - `Lifecycle\RecordPruner`: `prune()`.
 * - `RecoveryCodes\RecoveryCodeIssuance`: `generateRecoveryCodes()`.
 * - `RecoveryCodes\RecoveryCodeService`: `recoveryCodeStatus()`.
 * - `Context\AuthenticationContextContributor`: `authenticationContext()`.
 *
 * The built-in drivers are registered by `Drivers\DriverBindings` through the
 * same `extend()` API a consumer uses.
 *
 * It keeps nothing a request gave it, as one instance may outlive many requests
 * on a long-running server: it declares no property, resolves from
 * `Container::getInstance()` rather than the container it was built with,
 * builds a driver on every call rather than caching it, and refuses a new
 * container. Calling a method it does not declare is refused too, as Laravel's
 * manager would forward it to the default driver, outside attempts, proofs and
 * events.
 *
 * Exceeds the project's max-methods-per-class threshold by design: it is the
 * one surface the facade exposes, and each method only delegates.
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
     * Refuse a method the manager does not declare: Laravel's manager would
     * forward it to the default driver, outside attempts, proofs and events.
     * The arguments may hold a secret, so they are not named.
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
     * Get the default driver name.
     *
     * @return string
     */
    #[\Override]
    public function getDefaultDriver(): string
    {
        return 'totp';
    }

    /**
     * Build the named driver, the default one when none is named: on every
     * call, as a driver built here would otherwise keep the configuration and
     * sender of the request that first asked for it.
     *
     * @param  string|\UnitEnum|null  $driver
     * @return \SineMacula\Laravel\Mfa\Contracts\FactorDriver
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function driver($driver = null): mixed
    {
        // phpcs:ignore SlevomatCodingStandard.Namespaces.ReferenceUsedNamesOnly.ReferenceViaFullyQualifiedName
        $name = \Illuminate\Support\enum_value($driver) ?: $this->getDefaultDriver();

        /** @var \SineMacula\Laravel\Mfa\Contracts\FactorDriver */
        return $this->createDriver($name);
    }

    /**
     * Refuse a container: the inherited setter would keep a request's
     * application.
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
     * The requirement the current identity's sign-in on the current application
     * must meet, composed from the application's configured mode, the
     * identity's own requirement and its re-enrolment obligation: empty when it
     * needs nothing further, and without an MFA-capable identity.
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
     * Whether the current session is fresh enough for the named operation: the
     * stricter of the requirement the application configures for it and the one
     * given applies, either alone when the other is absent, and an operation
     * with neither is never fresh.
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
     * The refusal asking the caller to step up to the requirement, as the route
     * gate raises it: the requirement as given, the factors offered to the
     * caller, the operation as a label, and whether the identity has a factor
     * whose stored status is exactly `confirmed`. Nothing is added to the
     * requirement, and the operation adds no freshness; compose the requirement
     * first, as with `requirement()` and `Requirement::strictest()`. A pending
     * caller is reported as its pending session's identity; any other caller
     * serving nobody, or naming an identity that is not a person, has no
     * confirmed factor reported. It is returned, not thrown.
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
     * The proofs of the signed-in person's sign-in on the current application
     * that still count, oldest first: none without an MFA-capable person or a
     * sign-in, and none on a pending session.
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
     * The factors of the identity the request serves for listing them, as
     * summaries, the preferred one first: a pending session's when its
     * credential allows it, otherwise the signed-in person's; none when it
     * serves nobody. Every factor is listed, pending ones and those enrolled
     * through another application included.
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
     * One factor of the identity the request serves for listing them, as a
     * summary; `null` when it serves nobody or the id is not one of its
     * factors, whoever else's it may be.
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
     * The factors offered to the session the request serves, as summaries:
     * confirmed, of an enabled type and accepted after its first factor, the
     * preferred one first; none when it serves nobody.
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
     * Send a code for the identity's delivered factor, bound to its sign-in and
     * the purpose: for a pending session, its sign-in; for an active one, a
     * step-up unless `sign_in` is asked for. Verify under the same purpose.
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
     * Start an assertion request for the identity's passkey factor: its options
     * for the client, or the reason there are none, `not_found` when the
     * request serves nobody for verifying.
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
     * Verify a code for a factor, a code answering a challenge, a recovery code
     * or a passkey's assertion, for the purpose given: for a pending session,
     * its sign-in; for an active one, a step-up unless `sign_in` is asked for.
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
     * Start an enrolment for the person the request serves: a pending factor, a
     * grant that may confirm it, and by type a secret and its provisioning URI,
     * or a first code to the destination; or the reason it may not start.
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
     * Confirm the enrolment the grant holds with the first valid code, in the
     * session that started it: the factor, with any recovery codes that come
     * with it; or the reason it was not confirmed.
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
     * Send the code of the enrolment the grant holds again, renewing nothing.
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
     * Cancel the enrolment the grant holds; `false` for a grant that is not the
     * caller's.
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
     * Give the signed-in person's factor, enrolled through the current
     * application, a new label, with no step-up; a blank label is none.
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
     * Make the signed-in person's confirmed factor their preferred one, which
     * is offered first, with no step-up.
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
     * Remove the signed-in person's factor enrolled through the current
     * application, with a fresh step-up, or say why not.
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
     * Reset an identity that has lost its factors, for someone else, with a
     * reason: every factor, enrolment, recovery code, lockout, proof and
     * session goes, and whether it must enrol again is recorded. Who may reset
     * whom is the application's authorisation.
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
     * Lift the factor's temporary lockout, for the actor: whether a live one
     * was lifted. Failures in a row stay, and a factor disabled at the failure
     * ceiling stays disabled.
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
     * Lift the identity's temporary lockout, for the actor: whether a live one
     * was lifted. Failures in a row stay.
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
     * Delete everything the package holds for an identity that has been
     * deleted: its factors, enrolments, delivered codes, recovery codes,
     * passkey associations and factor state. The `HasFactors` trait does this
     * for an Eloquent identity; call it after deleting any other.
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
     * Delete abandoned enrolments, expired codes, used or replaced recovery
     * codes and ended throttle windows, and say how many of each went.
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
     * Generate a new recovery code set for the signed-in person, replacing any
     * earlier one, and answer with its codes, once, as secrets for the
     * response; or the reason it was refused, leaving the earlier set:
     * `not_fresh` unless the session is fresh enough for
     * `mfa.generate_recovery_codes` and reaches the level the application sets
     * for issuing them, and `not_found` without an MFA-capable person signed
     * in, or on a pending session.
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
     * Where the recovery code set of the identity the request serves for
     * listing factors stands, without a code: a pending session's when its
     * credential allows listing them, otherwise the signed-in person's; `null`
     * when it serves nobody.
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
     * The keys of the authentication context's `mfa` namespace for the caller's
     * own sign-in: its proofs as the proof store holds them, with its first
     * factor, given to `AuthenticationContextContributor::contributeFor()`. A
     * pending session, nobody and an identity that is not a person have the
     * neutral context.
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
     * Resolve the configured factor model class.
     *
     * Consumers wire the resolved class into their identity's
     * `morphMany(Mfa::factorModel(), 'authenticatable')` relation.
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
     * Call a custom driver creator with the application current at the time,
     * not the one the manager was built with.
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
     * Resolve a service from the application current at the time.
     *
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
