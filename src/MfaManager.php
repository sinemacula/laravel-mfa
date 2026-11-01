<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa;

use Illuminate\Support\Collection;
use Illuminate\Support\Manager;
use SineMacula\Laravel\Mfa\Codes\SendResult;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentService;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Factors\FactorService;
use SineMacula\Laravel\Mfa\Lifecycle\LifecycleService;
use SineMacula\Laravel\Mfa\Proofs\ProofService;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService;
use SineMacula\Laravel\Mfa\Requirements\RequirementService;
use SineMacula\Laravel\Mfa\Verification\VerificationService;

/**
 * MFA manager.
 *
 * The factor driver registry (Laravel's `Manager`, so `Mfa::extend()` works as
 * for any manager) and the package's single entry point. Every other method is
 * a one-line delegation to the service of the capability it belongs to,
 * resolved from the container on each call:
 *
 * - `Requirements\RequirementService`: whether MFA applies (`shouldUse()`).
 * - `Factors\FactorService`: the identity's factors and the factor model.
 * - `Proofs\ProofService`: the proofs the current sign-in has recorded
 *   (`proofs()`).
 * - `Verification\VerificationService`: `challenge()` and `verify()`.
 * - `Enrollment\EnrollmentService`: `enroll()`.
 * - `Lifecycle\LifecycleService`: `disable()`.
 * - `RecoveryCodes\RecoveryCodeService`: `issueBackupCodes()`.
 *
 * The operations that run a factor through its driver pass the manager itself
 * to their service, so they use this manager's driver registry. The built-in
 * drivers are registered by `Drivers\DriverBindings` and
 * `RecoveryCodes\RecoveryCodeBindings` through the same `extend()` API a
 * consumer uses.
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
     * Determine whether the current identity should use multi-factor
     * authentication.
     *
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function shouldUse(): bool
    {
        return $this->container->make(RequirementService::class)->shouldUse();
    }

    /**
     * Determine whether the current identity has at least one registered
     * authentication factor.
     *
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function isSetup(): bool
    {
        return $this->container->make(FactorService::class)->isSetup();
    }

    /**
     * The proofs of the current identity's sign-in on the current application
     * that still count, oldest first: none without an MFA-capable identity or a
     * sign-in.
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
     * Get the authentication factors for the current identity, or null if the
     * identity does not support multi-factor authentication.
     *
     * @formatter:off
     *
     * @return ?\Illuminate\Support\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\Factor>
     *
     * @formatter:on
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function getFactors(): ?Collection
    {
        return $this->container->make(FactorService::class)->getFactors();
    }

    /**
     * Issue a challenge for the given factor through the named driver, for the
     * purpose given: for a type that delivers codes, the outcome of sending one
     * bound to this session and the purpose; otherwise `null`.
     *
     * @param  string  $driver
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @return ?\SineMacula\Laravel\Mfa\Codes\SendResult
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\FactorDriverMismatchException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\FactorOwnershipMismatchException
     * @throws \Throwable
     */
    public function challenge(string $driver, Factor $factor, Purpose $purpose = Purpose::SIGN_IN): ?SendResult
    {
        return $this->container->make(VerificationService::class)->challenge($this, $driver, $factor, $purpose);
    }

    /**
     * Verify a submitted code against the given factor through the named
     * driver, for the purpose given.
     *
     * @param  string  $driver
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  string  $code
     * @param  \SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\FactorDriverMismatchException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\FactorOwnershipMismatchException
     */
    public function verify(string $driver, Factor $factor, #[\SensitiveParameter] string $code, Purpose $purpose = Purpose::SIGN_IN): bool
    {
        return $this->container->make(VerificationService::class)->verify($this, $driver, $factor, $code, $purpose);
    }

    /**
     * Enrol a freshly-built factor against the current identity.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\FactorOwnershipMismatchException
     */
    public function enroll(Factor $factor): void
    {
        $this->container->make(EnrollmentService::class)->enroll($factor);
    }

    /**
     * Disable a previously-enrolled factor for the current identity.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\FactorOwnershipMismatchException
     */
    public function disable(Factor $factor): void
    {
        $this->container->make(LifecycleService::class)->disable($factor);
    }

    /**
     * Issue a fresh batch of backup codes for the current identity, returning
     * the plaintext set exactly once.
     *
     * @param  ?int  $count
     * @return list<string>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
     */
    public function issueBackupCodes(?int $count = null): array
    {
        return $this->container->make(RecoveryCodeService::class)->issueBackupCodes($this, $count);
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
