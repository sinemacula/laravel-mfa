<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa;

use Illuminate\Support\Manager;
use SineMacula\Laravel\Mfa\Codes\SendResult;
use SineMacula\Laravel\Mfa\Context\CallerContextResolver;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentConfirmation;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentRequest;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentService;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentStart;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Events\Actor;
use SineMacula\Laravel\Mfa\Factors\FactorChange;
use SineMacula\Laravel\Mfa\Factors\FactorService;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use SineMacula\Laravel\Mfa\Lifecycle\FactorRemovalResult;
use SineMacula\Laravel\Mfa\Lifecycle\IdentityReset;
use SineMacula\Laravel\Mfa\Lifecycle\LifecycleService;
use SineMacula\Laravel\Mfa\Lifecycle\PruneResult;
use SineMacula\Laravel\Mfa\Lifecycle\RecordPruner;
use SineMacula\Laravel\Mfa\Proofs\ProofService;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeIssuance;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeStatus;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Requirements\RequirementService;
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
 * resolved from the container on each call:
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
 * - `Lifecycle\RecordPruner`: `prune()`.
 * - `RecoveryCodes\RecoveryCodeIssuance`: `generateRecoveryCodes()`.
 * - `RecoveryCodes\RecoveryCodeService`: `recoveryCodes()`.
 *
 * The built-in drivers are registered by `Drivers\DriverBindings` through the
 * same `extend()` API a consumer uses.
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
     * The requirement the current identity's sign-in on the current application
     * must meet, composed from the application's configured mode, the
     * identity's own requirement and its re-enrolment obligation: empty when it
     * needs nothing further, and without an MFA-capable identity.
     *
     * @return \SineMacula\Laravel\Mfa\Requirements\Requirement
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    public function requirement(): Requirement
    {
        return $this->container->make(RequirementService::class)->requirement();
    }

    /**
     * Whether the current session is fresh enough for the named operation: the
     * stricter of the requirement the application configures for it and the one
     * given applies, either alone when the other is absent, and an operation
     * with neither is never fresh.
     *
     * @param  string  $operation
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    public function isFresh(string $operation, ?Requirement $requirement = null): bool
    {
        return $this->container->make(RequirementService::class)->isFresh($operation, $requirement);
    }

    /**
     * The proofs of the signed-in person's sign-in on the current application
     * that still count, oldest first: none without an MFA-capable person or a
     * sign-in, and none on a pending session.
     *
     * @return list<\SineMacula\Laravel\Mfa\Proofs\Proof>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function proofs(): array
    {
        return $this->container->make(ProofService::class)->proofs();
    }

    /**
     * The factors of the identity the request serves for listing them, as
     * summaries, the preferred one first: a pending session's when its
     * credential allows it, otherwise the signed-in person's; none when it
     * serves nobody. Every factor is listed, pending ones and those enrolled
     * through another application included.
     *
     * @return list<\SineMacula\Laravel\Mfa\Factors\FactorSummary>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function factors(): array
    {
        return $this->container->make(FactorService::class)->factors();
    }

    /**
     * One factor of the identity the request serves for listing them, as a
     * summary; `null` when it serves nobody or the id is not one of its
     * factors, whoever else's it may be.
     *
     * @param  mixed  $factorId
     * @return ?\SineMacula\Laravel\Mfa\Factors\FactorSummary
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function factor(mixed $factorId): ?FactorSummary
    {
        return $this->container->make(FactorService::class)->factor($factorId);
    }

    /**
     * The factors offered to the session the request serves, as summaries:
     * confirmed, of an enabled type and accepted after its first factor, the
     * preferred one first; none when it serves nobody.
     *
     * @return list<\SineMacula\Laravel\Mfa\Factors\FactorSummary>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    public function offeredFactors(): array
    {
        return $this->container->make(FactorOffers::class)->offered();
    }

    /**
     * Send a code for the identity's delivered factor, bound to its sign-in and
     * the purpose: for a pending session, its sign-in; for an active one, a
     * step-up unless `sign_in` is asked for. Verify under the same purpose.
     *
     * @param  mixed  $factorId
     * @param  ?\SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @return \SineMacula\Laravel\Mfa\Codes\SendResult
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Throwable
     */
    public function sendCode(mixed $factorId, ?Purpose $purpose = null): SendResult
    {
        return $this->container->make(ChallengeRequests::class)->sendCode($factorId, $purpose);
    }

    /**
     * The options of an assertion request for the identity's passkey factor;
     * none when the request serves nobody for verifying.
     *
     * @param  mixed  $factorId
     * @param  ?\SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @return array<string, mixed>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     * @throws \Throwable
     */
    public function requestAssertion(mixed $factorId, ?Purpose $purpose = null): array
    {
        return $this->container->make(ChallengeRequests::class)->requestAssertion($factorId, $purpose);
    }

    /**
     * Verify a code for a factor, a code answering a challenge, a recovery code
     * or a passkey's assertion, for the purpose given: for a pending session,
     * its sign-in; for an active one, a step-up unless `sign_in` is asked for.
     *
     * @param  \SineMacula\Laravel\Mfa\Verification\Submission  $submission
     * @param  ?\SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @return \SineMacula\Laravel\Mfa\Verification\VerificationResult
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Throwable
     */
    public function verify(#[\SensitiveParameter] Submission $submission, ?Purpose $purpose = null): VerificationResult
    {
        return $this->container->make(VerificationService::class)->verify($submission, $purpose);
    }

    /**
     * Start an enrolment for the person the request serves: a pending factor, a
     * grant that may confirm it, and by type a secret and its provisioning URI,
     * or a first code to the destination; or the reason it may not start.
     *
     * @param  \SineMacula\Laravel\Mfa\Enrollment\EnrollmentRequest  $request
     * @return \SineMacula\Laravel\Mfa\Enrollment\EnrollmentStart
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Throwable
     */
    public function startEnrollment(#[\SensitiveParameter] EnrollmentRequest $request): EnrollmentStart
    {
        return $this->container->make(EnrollmentService::class)->start($request);
    }

    /**
     * Confirm the enrolment the grant holds with the first valid code, in the
     * session that started it: the factor, with any recovery codes that come
     * with it; or the reason it was not confirmed.
     *
     * @param  \SineMacula\Laravel\Mfa\Secrets\RevealedSecret|string  $grant
     * @param  string  $code
     * @return \SineMacula\Laravel\Mfa\Enrollment\EnrollmentConfirmation
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Throwable
     */
    public function confirmEnrollment(#[\SensitiveParameter] RevealedSecret|string $grant, #[\SensitiveParameter] string $code): EnrollmentConfirmation
    {
        return $this->container->make(EnrollmentService::class)->confirm($grant, $code);
    }

    /**
     * Send the code of the enrolment the grant holds again, renewing nothing.
     *
     * @param  \SineMacula\Laravel\Mfa\Secrets\RevealedSecret|string  $grant
     * @return \SineMacula\Laravel\Mfa\Codes\SendResult
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Throwable
     */
    public function resendEnrollmentCode(#[\SensitiveParameter] RevealedSecret|string $grant): SendResult
    {
        return $this->container->make(EnrollmentService::class)->resend($grant);
    }

    /**
     * Cancel the enrolment the grant holds; `false` for a grant that is not the
     * caller's.
     *
     * @param  \SineMacula\Laravel\Mfa\Secrets\RevealedSecret|string  $grant
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Throwable
     *
     * @imperative
     */
    public function cancelEnrollment(#[\SensitiveParameter] RevealedSecret|string $grant): bool
    {
        return $this->container->make(EnrollmentService::class)->cancel($grant);
    }

    /**
     * Give the signed-in person's factor, enrolled through the current
     * application, a new label, with no step-up; a blank label is none.
     *
     * @param  mixed  $factorId
     * @param  ?string  $label
     * @return \SineMacula\Laravel\Mfa\Factors\FactorChange
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    public function renameFactor(mixed $factorId, ?string $label): FactorChange
    {
        return $this->container->make(FactorService::class)->rename($factorId, $label);
    }

    /**
     * Make the signed-in person's confirmed factor their preferred one, which
     * is offered first, with no step-up.
     *
     * @param  mixed  $factorId
     * @return \SineMacula\Laravel\Mfa\Factors\FactorChange
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Throwable
     */
    public function setPreferredFactor(mixed $factorId): FactorChange
    {
        return $this->container->make(FactorService::class)->setPreferred($factorId);
    }

    /**
     * Remove the signed-in person's factor enrolled through the current
     * application, with a fresh step-up, or say why not.
     *
     * @param  mixed  $factorId
     * @return \SineMacula\Laravel\Mfa\Lifecycle\FactorRemovalResult
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Throwable
     */
    public function removeFactor(mixed $factorId): FactorRemovalResult
    {
        return $this->container->make(LifecycleService::class)->removeFactor($factorId);
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
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    public function resetIdentity(MultiFactorAuthenticatable $identity, Actor $actor, string $reason, bool $requireReenrollment = true): void
    {
        $this->container->make(IdentityReset::class)->reset($identity, $actor, $reason, $requireReenrollment);
    }

    /**
     * Lift the factor's temporary lockout, for the actor: whether a live one
     * was lifted. Failures in a row stay, and a factor disabled at the failure
     * ceiling stays disabled.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  mixed  $factorId
     * @param  \SineMacula\Laravel\Mfa\Events\Actor  $actor
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Throwable
     *
     * @imperative
     */
    public function unlockFactor(MultiFactorAuthenticatable $identity, mixed $factorId, Actor $actor): bool
    {
        return $this->container->make(LifecycleService::class)->unlockFactor($identity, $factorId, $actor);
    }

    /**
     * Lift the identity's temporary lockout, for the actor: whether a live one
     * was lifted. Failures in a row stay.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Events\Actor  $actor
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Throwable
     *
     * @imperative
     */
    public function unlockIdentity(MultiFactorAuthenticatable $identity, Actor $actor): bool
    {
        return $this->container->make(LifecycleService::class)->unlockIdentity($identity, $actor);
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
        return ($this->container->make(RecordPruner::class))();
    }

    /**
     * Generate a new recovery code set for the signed-in person, replacing any
     * earlier one, and return its codes, once, as secrets for the response:
     * refused as `not_fresh` unless the session is fresh enough for
     * `mfa.generate_recovery_codes` and reaches the level the application sets
     * for issuing them; none without an MFA-capable person signed in, or on a
     * pending session.
     *
     * @return list<\SineMacula\Laravel\Mfa\Secrets\RevealedSecret>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     * @throws \Throwable
     */
    public function generateRecoveryCodes(): array
    {
        return $this->container->make(RecoveryCodeIssuance::class)->generate();
    }

    /**
     * Where the recovery code set of the identity the request serves for
     * listing factors stands, without a code: a pending session's when its
     * credential allows listing them, otherwise the signed-in person's; `null`
     * when it serves nobody.
     *
     * @return ?\SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeStatus
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function recoveryCodes(): ?RecoveryCodeStatus
    {
        $identity = $this->container->make(CallerContextResolver::class)->resolve(PendingAction::LIST_FACTORS)?->identity;

        return $identity === null ? null : $this->container->make(RecoveryCodeService::class)->status($identity);
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
        return $this->container->make(FactorService::class)->factorModel();
    }
}
