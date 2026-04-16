<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa;

use Carbon\Carbon;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Mail\Mailer;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Manager;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Contracts\FactorDriver;
use SineMacula\Laravel\Mfa\Contracts\MfaPolicy;
use SineMacula\Laravel\Mfa\Contracts\MfaVerificationStore;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\SmsGateway;
use SineMacula\Laravel\Mfa\Drivers\BackupCodeDriver;
use SineMacula\Laravel\Mfa\Drivers\EmailDriver;
use SineMacula\Laravel\Mfa\Drivers\SmsDriver;
use SineMacula\Laravel\Mfa\Drivers\TotpDriver;
use SineMacula\Laravel\Mfa\Enums\MfaVerificationFailureReason;
use SineMacula\Laravel\Mfa\Events\MfaChallengeIssued;
use SineMacula\Laravel\Mfa\Events\MfaVerificationFailed;
use SineMacula\Laravel\Mfa\Events\MfaVerified;
use SineMacula\Laravel\Mfa\Mail\MfaCodeMessage;

/**
 * MFA manager.
 *
 * Orchestrates the multi-factor authentication lifecycle on top of the
 * pluggable `FactorDriver` / `Factor` / `MfaVerificationStore` contracts.
 * Responsibilities split cleanly between this class and its collaborators:
 *
 * - Drivers implement per-factor-type verification and challenge transport.
 * - Factors model the persisted verification state (attempts, lockouts,
 *   verification timestamps).
 * - The verification store owns the identity-level "last verified at"
 *   signal that `hasExpired()` reads.
 * - The MFA policy answers whether an identity should be forced into MFA
 *   beyond its own preference.
 *
 * The manager wires them together, dispatches the lifecycle events, and
 * caches per-request read results so middleware stacks that call
 * `shouldUse()` / `isSetup()` / `hasExpired()` in sequence do not incur
 * redundant work.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
class MfaManager extends Manager
{
    /** @var string Cache key for the setup state */
    private const string CACHE_KEY_SETUP = 'setup';

    /** @var string Cache key for the factors collection */
    private const string CACHE_KEY_FACTORS = 'factors';

    /** @var array<string, mixed> Runtime cache for MFA state */
    private array $cache = [];

    /**
     * Get the default driver name.
     *
     * @return string
     */
    public function getDefaultDriver(): string
    {
        return 'totp';
    }

    /**
     * Determine whether the current identity should use multi-factor
     * authentication.
     *
     * Returns true when the identity's own preference requests MFA, or
     * when the bound `MfaPolicy` enforces it externally (for example on
     * every member of an organisation that mandates MFA). The default
     * policy binding (`NullMfaPolicy`) always returns false, so standalone
     * apps behave purely on the identity's own `shouldUseMultiFactor()`
     * preference.
     *
     * @return bool
     */
    public function shouldUse(): bool
    {
        $identity = $this->resolveIdentity();

        if ($identity === null) {
            return false;
        }

        if ($identity->shouldUseMultiFactor()) {
            return true;
        }

        return $this->resolvePolicy()->shouldEnforce($identity);
    }

    /**
     * Determine whether the current identity has at least one registered
     * authentication factor.
     *
     * @return bool
     */
    public function isSetup(): bool
    {
        $identity = $this->resolveIdentity();

        if ($identity === null) {
            return false;
        }

        /** @var bool */
        return $this->cached(
            self::CACHE_KEY_SETUP,
            $identity,
            static fn (): bool => $identity->isMfaEnabled(),
        );
    }

    /**
     * Determine whether the current identity has ever completed a
     * successful MFA verification (on any device tracked by the bound
     * verification store).
     *
     * @return bool
     */
    public function hasEverVerified(): bool
    {
        $identity = $this->resolveIdentity();

        if ($identity === null) {
            return false;
        }

        return $this->resolveStore()->lastVerifiedAt($identity) !== null;
    }

    /**
     * Determine whether the current identity's MFA verification has
     * expired. Returns true when no prior verification exists OR the
     * recorded verification is older than the configured expiry window.
     *
     * @param  ?int  $expiresAfter
     * @return bool
     */
    public function hasExpired(?int $expiresAfter = null): bool
    {
        $identity = $this->resolveIdentity();

        if ($identity === null) {
            return true;
        }

        $verifiedAt = $this->resolveStore()->lastVerifiedAt($identity);

        if ($verifiedAt === null) {
            return true;
        }

        if ($expiresAfter === null) {
            $expiresAfter = $this->resolveDefaultExpiry();
        }

        // `expiresAfter === 0` is the documented "require verification on
        // every request" setting; treat any prior verification as expired.
        if ($expiresAfter <= 0) {
            return true;
        }

        $elapsed = $verifiedAt->diffInMinutes(Carbon::now(), false);

        // Negative elapsed means `verifiedAt` is in the future (clock skew
        // or malicious store write). Treat as expired rather than trusting
        // a future-dated verification.
        if ($elapsed < 0) {
            return true;
        }

        return $elapsed > $expiresAfter;
    }

    /**
     * Record that the current identity has completed a successful MFA
     * verification. Writes through to the bound verification store.
     *
     * @return void
     */
    public function markVerified(): void
    {
        $identity = $this->resolveIdentity();

        if ($identity === null) {
            return;
        }

        $this->resolveStore()->markVerified($identity);
    }

    /**
     * Clear any stored verification timestamp for the current identity.
     *
     * @return void
     */
    public function forgetVerification(): void
    {
        $identity = $this->resolveIdentity();

        if ($identity === null) {
            return;
        }

        $this->resolveStore()->forget($identity);
    }

    /**
     * Clear the MFA state cache.
     *
     * Optionally scope the clear to a specific identity. When no identity
     * is provided, the entire cache is flushed.
     *
     * @param  ?\Illuminate\Contracts\Auth\Authenticatable  $identity
     * @return void
     */
    public function clearCache(?Authenticatable $identity = null): void
    {
        if ($identity === null) {
            $this->cache = [];

            return;
        }

        $prefix = $this->getCachePrefix($identity);

        $this->cache = array_filter(
            $this->cache,
            static fn (string $key): bool => !str_starts_with($key, $prefix),
            ARRAY_FILTER_USE_KEY,
        );
    }

    /**
     * Get the authentication factors for the current identity.
     *
     * Returns null if the identity does not support multi-factor
     * authentication. The result is cached for the duration of the
     * request.
     *
     * @formatter:off
     *
     * @return ?\Illuminate\Support\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\Factor>
     *
     * @formatter:on
     */
    public function getFactors(): ?Collection
    {
        $identity = $this->resolveIdentity();

        if ($identity === null) {
            return null;
        }

        return $this->cached(
            self::CACHE_KEY_FACTORS,
            $identity,
            static fn (): Collection => $identity->authFactors()->get()->toBase(),
        );
    }

    /**
     * Issue a challenge for the given factor through the named driver.
     *
     * Dispatches `MfaChallengeIssued` after delegating to the driver's
     * `issueChallenge()` implementation — for delivery drivers (email,
     * SMS) the challenge is sent; for implicit drivers (TOTP) this is a
     * signal that a verification window is now active.
     *
     * @param  string  $driver
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @return void
     */
    public function challenge(string $driver, Factor $factor): void
    {
        // A fresh challenge invalidates any prior failed-attempt state so
        // a user who locked themselves out on a stale code can recover by
        // requesting a new one.
        if ($factor instanceof EloquentFactor) {
            $factor->resetAttempts();
        }

        $this->resolveDriver($driver)->issueChallenge($factor);

        if ($factor instanceof EloquentFactor) {
            $factor->persist();
        }

        $identity = $this->resolveIdentity();

        if ($identity === null) {
            return;
        }

        $this->resolveEvents()->dispatch(
            new MfaChallengeIssued($identity, $factor, $driver),
        );
    }

    /**
     * Verify a submitted code against the given factor through the named
     * driver.
     *
     * This is the orchestration entry point that most consumers call. The
     * manager:
     *
     * - Rejects the attempt when the factor is locked.
     * - Runs the driver's verification logic.
     * - On success: resets attempts, stamps the factor's verified-at,
     *   clears any pending code, records the identity-level verification
     *   through the bound store, dispatches `MfaVerified`.
     * - On failure: increments attempts, applies a lockout once the
     *   configured per-driver threshold is reached, dispatches
     *   `MfaVerificationFailed` with a machine-readable reason.
     *
     * @param  string  $driver
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  string  $code
     * @return bool
     */
    public function verify(
        string $driver,
        Factor $factor,
        #[\SensitiveParameter]
        string $code,
    ): bool {
        $identity = $this->resolveIdentity();

        if ($identity === null) {
            return false;
        }

        if ($factor->isLocked()) {
            $this->dispatchFailure(
                $identity,
                $factor,
                $driver,
                MfaVerificationFailureReason::FactorLocked,
            );

            return false;
        }

        $valid = $this->resolveDriver($driver)->verify($factor, $code);

        if ($factor instanceof EloquentFactor) {
            $this->applyVerificationOutcome($factor, $driver, $valid);
        }

        if ($valid) {
            $this->resolveStore()->markVerified($identity);
            $this->clearCache($identity);

            $this->resolveEvents()->dispatch(
                new MfaVerified($identity, $factor, $driver),
            );

            return true;
        }

        $this->dispatchFailure(
            $identity,
            $factor,
            $driver,
            $this->classifyFailure($factor),
        );

        return false;
    }

    /**
     * Create the TOTP driver.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\FactorDriver
     */
    protected function createTotpDriver(): FactorDriver
    {
        /** @var array{window?: int} $config */
        $config = $this->getDriverConfig('totp');

        return new TotpDriver(
            window: $config['window'] ?? 1,
        );
    }

    /**
     * Create the email driver.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\FactorDriver
     */
    protected function createEmailDriver(): FactorDriver
    {
        /**
         * @var array{
         *     code_length?: int,
         *     expiry?: int,
         *     max_attempts?: int,
         *     alphabet?: ?string,
         *     mailable?: class-string<\SineMacula\Laravel\Mfa\Mail\MfaCodeMessage>
         * } $config
         */
        $config = $this->getDriverConfig('email');

        return new EmailDriver(
            mailer: $this->container->make(Mailer::class),
            mailable: $config['mailable']        ?? MfaCodeMessage::class,
            codeLength: $config['code_length']   ?? 6,
            expiry: $config['expiry']            ?? 10,
            maxAttempts: $config['max_attempts'] ?? 3,
            alphabet: $config['alphabet']        ?? null,
        );
    }

    /**
     * Create the SMS driver.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\FactorDriver
     */
    protected function createSmsDriver(): FactorDriver
    {
        /**
         * @var array{
         *     code_length?: int,
         *     expiry?: int,
         *     max_attempts?: int,
         *     alphabet?: ?string,
         *     message_template?: string
         * } $config
         */
        $config = $this->getDriverConfig('sms');

        return new SmsDriver(
            gateway: $this->container->make(SmsGateway::class),
            messageTemplate: $config['message_template']
                                                 ?? 'Your verification code is: :code',
            codeLength: $config['code_length']   ?? 6,
            expiry: $config['expiry']            ?? 10,
            maxAttempts: $config['max_attempts'] ?? 3,
            alphabet: $config['alphabet']        ?? null,
        );
    }

    /**
     * Create the backup-code driver.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\FactorDriver
     */
    protected function createBackupCodeDriver(): FactorDriver
    {
        /**
         * @var array{
         *     code_length?: int,
         *     alphabet?: string,
         *     code_count?: int
         * } $config
         */
        $config = $this->getDriverConfig('backup_code');

        return new BackupCodeDriver(
            codeLength: $config['code_length'] ?? 10,
            alphabet: $config['alphabet']
                                             ?? '23456789ABCDEFGHJKLMNPQRSTUVWXYZ',
            codeCount: $config['code_count'] ?? 10,
        );
    }

    /**
     * Resolve the bound MFA policy.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\MfaPolicy
     */
    protected function resolvePolicy(): MfaPolicy
    {
        /** @var \SineMacula\Laravel\Mfa\Contracts\MfaPolicy */
        return $this->container->make(MfaPolicy::class);
    }

    /**
     * Resolve the bound MFA verification store.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\MfaVerificationStore
     */
    protected function resolveStore(): MfaVerificationStore
    {
        /** @var \SineMacula\Laravel\Mfa\Contracts\MfaVerificationStore */
        return $this->container->make(MfaVerificationStore::class);
    }

    /**
     * Resolve the event dispatcher.
     *
     * @return \Illuminate\Contracts\Events\Dispatcher
     */
    protected function resolveEvents(): Dispatcher
    {
        return $this->container->make(Dispatcher::class);
    }

    /**
     * Resolve the named factor driver, narrowed to the
     * `FactorDriver` contract for downstream callers.
     *
     * The base manager's `driver()` returns `mixed`; this helper
     * locks the return type so callers do not need to hint or
     * assert at every site.
     *
     * @param  string  $driver
     * @return \SineMacula\Laravel\Mfa\Contracts\FactorDriver
     */
    protected function resolveDriver(string $driver): FactorDriver
    {
        $instance = $this->driver($driver);

        if (!$instance instanceof FactorDriver) {
            throw new \LogicException(sprintf('Driver [%s] must implement %s.', $driver, FactorDriver::class));
        }

        return $instance;
    }

    /**
     * Resolve the currently authenticated identity if it is MFA-capable.
     *
     * @return ?\SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    private function resolveIdentity(): ?MultiFactorAuthenticatable
    {
        $identity = Auth::user();

        return $identity instanceof MultiFactorAuthenticatable
            ? $identity
            : null;
    }

    /**
     * Apply the verification outcome to a persistable factor and save.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  string  $driver
     * @param  bool  $valid
     * @return void
     */
    private function applyVerificationOutcome(
        EloquentFactor $factor,
        string $driver,
        bool $valid,
    ): void {
        if ($valid) {
            $factor->recordVerification();
            $factor->persist();

            return;
        }

        $factor->recordAttempt();

        $maxAttempts = $this->resolveMaxAttempts($driver);

        if ($maxAttempts > 0 && $factor->getAttempts() >= $maxAttempts) {
            $factor->applyLockout(
                Carbon::now()->addMinutes($this->resolveLockoutMinutes()),
            );
        }

        $factor->persist();
    }

    /**
     * Classify the failure reason for a non-successful verification.
     *
     * TOTP-shaped drivers fail with `SecretMissing` when the factor has no
     * persistent secret (expected TOTP enrolment never completed). OTP-
     * delivery drivers fail with `CodeMissing` when no challenge has been
     * issued, `CodeExpired` when the pending code has aged out, and
     * `CodeInvalid` for all other comparison mismatches.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @return \SineMacula\Laravel\Mfa\Enums\MfaVerificationFailureReason
     */
    private function classifyFailure(Factor $factor): MfaVerificationFailureReason
    {
        $expiresAt = $factor->getExpiresAt();
        $code      = $factor->getCode();
        $secret    = $factor->getSecret();

        if ($code === null && $secret === null) {
            return MfaVerificationFailureReason::SecretMissing;
        }

        if ($expiresAt !== null && $expiresAt->isPast()) {
            return MfaVerificationFailureReason::CodeExpired;
        }

        if ($code === null) {
            // Must be a TOTP-shaped factor (secret non-null per the early
            // return above). The submitted code didn't match the derived
            // TOTP window.
            return MfaVerificationFailureReason::CodeInvalid;
        }

        if ($expiresAt === null) {
            // Pending code exists but has no expiry — treat as missing.
            return MfaVerificationFailureReason::CodeMissing;
        }

        return MfaVerificationFailureReason::CodeInvalid;
    }

    /**
     * Dispatch a `MfaVerificationFailed` event.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $identity
     * @param  ?\SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  string  $driver
     * @param  \SineMacula\Laravel\Mfa\Enums\MfaVerificationFailureReason  $reason
     * @return void
     */
    private function dispatchFailure(
        Authenticatable $identity,
        ?Factor $factor,
        string $driver,
        MfaVerificationFailureReason $reason,
    ): void {
        $this->resolveEvents()->dispatch(
            new MfaVerificationFailed($identity, $factor, $driver, $reason),
        );
    }

    /**
     * Resolve the max-attempts threshold for a driver.
     *
     * @param  string  $driver
     * @return int
     */
    private function resolveMaxAttempts(string $driver): int
    {
        /** @var mixed $value */
        $value = $this->getDriverConfig($driver)['max_attempts'] ?? 0;

        return is_int($value) ? $value : 0;
    }

    /**
     * Resolve the lockout duration in minutes.
     *
     * @return int
     */
    private function resolveLockoutMinutes(): int
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->container->make('config');

        /** @var mixed $value */
        $value = $config->get('mfa.lockout_minutes', 15);

        return is_int($value) ? $value : 15;
    }

    /**
     * Resolve the default expiry window in minutes.
     *
     * @return int
     */
    private function resolveDefaultExpiry(): int
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->container->make('config');

        /** @var mixed $value */
        $value = $config->get('mfa.default_expiry', 20160);

        if (is_int($value)) {
            return $value;
        }

        return is_numeric($value) ? (int) $value : 0;
    }

    /**
     * Get the configuration for a specific driver.
     *
     * @param  string  $driver
     * @return array<string, mixed>
     */
    private function getDriverConfig(string $driver): array
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->container->make('config');

        /** @var array<string, mixed> */
        return $config->get("mfa.drivers.{$driver}", []);
    }

    /**
     * Retrieve a cached value or compute and store it.
     *
     * @template T
     *
     * @param  string  $key
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $identity
     * @param  callable(): T  $callback
     * @return T
     */
    private function cached(
        string $key,
        Authenticatable $identity,
        callable $callback,
    ): mixed {
        $cacheKey = $this->getCachePrefix($identity) . $key;

        if (!array_key_exists($cacheKey, $this->cache)) {
            $this->cache[$cacheKey] = $callback();
        }

        return $this->cache[$cacheKey];
    }

    /**
     * Get the cache key prefix for the given identity.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $identity
     * @return string
     */
    private function getCachePrefix(Authenticatable $identity): string
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->container->make('config');

        /** @var string $prefix */
        $prefix = $config->get('mfa.cache_prefix', 'mfa:');

        $identifier = $identity->getAuthIdentifier();

        $suffix = is_string($identifier) || is_int($identifier)
            ? (string) $identifier
            : '';

        return $prefix . $suffix . ':';
    }
}
