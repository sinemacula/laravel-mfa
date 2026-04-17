<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa;

use Carbon\Carbon;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Manager;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Contracts\FactorDriver;
use SineMacula\Laravel\Mfa\Contracts\MfaPolicy;
use SineMacula\Laravel\Mfa\Contracts\MfaVerificationStore;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Drivers\BackupCodeDriver;
use SineMacula\Laravel\Mfa\Enums\MfaVerificationFailureReason;
use SineMacula\Laravel\Mfa\Events\MfaChallengeIssued;
use SineMacula\Laravel\Mfa\Events\MfaFactorDisabled;
use SineMacula\Laravel\Mfa\Events\MfaFactorEnrolled;
use SineMacula\Laravel\Mfa\Events\MfaVerificationFailed;
use SineMacula\Laravel\Mfa\Events\MfaVerified;
use SineMacula\Laravel\Mfa\Exceptions\FactorOwnershipMismatchException;
use SineMacula\Laravel\Mfa\Exceptions\InvalidFactorModelException;
use SineMacula\Laravel\Mfa\Models\Factor as ShippedFactorModel;

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
 * redundant work. Built-in driver factories live in `MfaServiceProvider`
 * and are registered against the manager through the standard `extend()`
 * API at construction time, keeping this class free of per-driver
 * construction logic.
 *
 * The class exceeds the project's max-methods-per-class threshold —
 * the Manager pattern's coordination role across drivers, factors,
 * verification store, policy, and cache is intrinsic. Splitting into
 * traits would shuffle the methods rather than reduce coupling and
 * obscure the orchestration surface that consumers integrate against.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @SuppressWarnings("php:S1448")
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
     * Resolve the configured factor model class.
     *
     * Reads `config('mfa.factor.model')`; falls back to the shipped
     * `Factor` model when the key is unset (matches the published
     * default config). Validates that the configured value is a class
     * string implementing the package's `EloquentFactor` contract —
     * misconfigured values throw `InvalidFactorModelException` rather
     * than silently degrading to the default, since the seam exists
     * precisely so consumers can swap the model and a typo would
     * otherwise be invisible.
     *
     * Consumers wire the resolved class into their identity model's
     * `morphMany(Mfa::factorModel(), 'authenticatable')` relation, and
     * the package itself uses it in any code path that needs to
     * instantiate a fresh factor (for example backup-code rotation).
     *
     * @return class-string<\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>
     */
    public function factorModel(): string
    {
        $config = $this->container->make('config');

        /** @var mixed $configured */
        $configured = $config->get('mfa.factor.model', ShippedFactorModel::class);

        // A null value (consumer cleared the env var, or the config
        // entry is missing entirely) falls through to the shipped
        // model — matches the fresh-install contract documented in
        // `config/mfa.php`.
        if ($configured === null) {
            return ShippedFactorModel::class;
        }

        if (!is_string($configured) || $configured === '') {
            throw new InvalidFactorModelException(sprintf('mfa.factor.model must be a class string; got [%s].', get_debug_type($configured)));
        }

        if (!class_exists($configured)) {
            throw new InvalidFactorModelException(sprintf('mfa.factor.model class [%s] does not exist.', $configured));
        }

        if (!is_subclass_of($configured, EloquentFactor::class) || !is_subclass_of($configured, Model::class)) {
            throw new InvalidFactorModelException(sprintf('mfa.factor.model class [%s] must extend %s and implement %s.', $configured, Model::class, EloquentFactor::class));
        }

        /** @var class-string<\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor> $configured */
        return $configured;
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

        /** @var \SineMacula\Laravel\Mfa\Contracts\MfaPolicy $policy */
        $policy = $this->container->make(MfaPolicy::class);

        return $policy->shouldEnforce($identity);
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

        $cacheKey = $this->getCachePrefix($identity) . self::CACHE_KEY_SETUP;

        if (!array_key_exists($cacheKey, $this->cache)) {
            $this->cache[$cacheKey] = $identity->isMfaEnabled();
        }

        /** @var bool */
        return $this->cache[$cacheKey];
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

        /** @var \SineMacula\Laravel\Mfa\Contracts\MfaVerificationStore $store */
        $store = $this->container->make(MfaVerificationStore::class);

        return $store->lastVerifiedAt($identity) !== null;
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

        /** @var \SineMacula\Laravel\Mfa\Contracts\MfaVerificationStore $store */
        $store = $this->container->make(MfaVerificationStore::class);

        $verifiedAt = $store->lastVerifiedAt($identity);
        $window     = $expiresAfter ?? $this->resolveIntConfig(
            'mfa.default_expiry',
            default: 20160,
            malformedFallback: 0,
        );

        // `verifiedAt === null` means no prior verification exists.
        // `window <= 0` is the documented "require verification on every
        // request" setting and treats any prior verification as expired.
        // A negative `elapsed` means `verifiedAt` is in the future (clock
        // skew or a malicious store write) — treat as expired rather than
        // trusting a future-dated verification.
        $elapsed = $verifiedAt?->diffInMinutes(Carbon::now(), false);

        return $verifiedAt === null
            || $window <= 0
            || $elapsed === null
            || $elapsed < 0
            || $elapsed > $window;
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

        /** @var \SineMacula\Laravel\Mfa\Contracts\MfaVerificationStore $store */
        $store = $this->container->make(MfaVerificationStore::class);

        $store->markVerified($identity);
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

        /** @var \SineMacula\Laravel\Mfa\Contracts\MfaVerificationStore $store */
        $store = $this->container->make(MfaVerificationStore::class);

        $store->forget($identity);
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

        $cacheKey = $this->getCachePrefix($identity) . self::CACHE_KEY_FACTORS;

        if (!array_key_exists($cacheKey, $this->cache)) {
            $this->cache[$cacheKey] = $identity->authFactors()->get()->toBase();
        }

        /** @var \Illuminate\Support\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\Factor> */
        return $this->cache[$cacheKey];
    }

    /**
     * Issue a challenge for the given factor through the named driver.
     *
     * Dispatches `MfaChallengeIssued` after delegating to the driver's
     * `issueChallenge()` implementation — for delivery drivers (email,
     * SMS) the challenge is sent; for implicit drivers (TOTP) this is a
     * signal that a verification window is now active.
     *
     * Throws `FactorOwnershipMismatchException` when the supplied factor
     * does not belong to the current identity, closing the cross-account
     * factor-tampering primitive.
     *
     * @param  string  $driver
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @return void
     */
    public function challenge(string $driver, Factor $factor): void
    {
        $identity = $this->resolveIdentity();

        if ($identity === null) {
            return;
        }

        $this->assertFactorOwnership($factor, $identity);

        // OTP-issuing drivers (email, SMS) reset the attempt counter and
        // persist the freshly minted code from inside `issueChallenge()` —
        // the reset is paired with a fresh secret and so cannot be used
        // to wipe a lockout without rotating credentials. TOTP and backup
        // codes have no per-challenge secret to mint and no state to
        // persist, so their `issueChallenge()` is a no-op and the manager
        // preserves their lockout state across challenge calls.
        $this->resolveDriver($driver)->issueChallenge($factor);

        $events = $this->container->make(Dispatcher::class);
        $events->dispatch(new MfaChallengeIssued($identity, $factor, $driver));
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
     * Throws `FactorOwnershipMismatchException` when the supplied factor
     * does not belong to the current identity, closing the cross-account
     * MFA-bypass primitive.
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

        $this->assertFactorOwnership($factor, $identity);

        $events = $this->container->make(Dispatcher::class);

        if ($factor->isLocked()) {
            $events->dispatch(new MfaVerificationFailed($identity, $factor, $driver, MfaVerificationFailureReason::FactorLocked));

            return false;
        }

        $valid = $this->resolveDriver($driver)->verify($factor, $code);

        if ($factor instanceof EloquentFactor) {
            $this->applyVerificationOutcome($factor, $driver, $valid);
        }

        $this->finaliseVerification($identity, $factor, $driver, $valid, $events);

        return $valid;
    }

    /**
     * Enrol a freshly-built factor against the current identity.
     *
     * The consumer constructs the factor (TOTP secret already generated,
     * email recipient already set, backup-code hash already populated,
     * etc.); this method stamps the factor's ownership onto the current
     * identity, persists it (via the `EloquentFactor::persist()` seam),
     * invalidates the identity's setup-state cache so the next
     * `isSetup()` call sees the new factor, and dispatches
     * `MfaFactorEnrolled` for downstream subscribers (audit log, ops
     * notifications, access-policy recalculation).
     *
     * Ownership is stamped, never trusted: any caller-supplied morph
     * columns on an Eloquent factor are overwritten with the current
     * identity's class and identifier, so a consumer cannot enrol a
     * factor against a different account by passing pre-populated
     * relation columns. Non-Eloquent factor implementations must
     * already report the current identity through `getAuthenticatable()`;
     * mismatches throw `FactorOwnershipMismatchException`.
     *
     * No-op when no MFA-capable identity is resolvable from the guard —
     * matches the established `markVerified()` / `forgetVerification()`
     * shape so consumers can call this unconditionally during a sign-up
     * flow without guarding against unauthenticated requests.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @return void
     */
    public function enrol(Factor $factor): void
    {
        $identity = $this->resolveIdentity();

        if ($identity === null) {
            return;
        }

        if ($factor instanceof EloquentFactor && $factor instanceof Model) {
            // Stamping ownership only makes sense for a brand-new factor.
            // If the row already exists (e.g. the consumer fetched it by
            // primary key from request input) we MUST NOT silently
            // overwrite its morph columns — that would let an attacker
            // hijack any factor row whose ID they could enumerate. Treat
            // an existing row as an attempt to re-enrol it under the
            // current identity and require ownership to already match.
            if ($factor->exists) {
                $this->assertFactorOwnership($factor, $identity);
            } else {
                $relation = $factor->authenticatable();

                $factor->setAttribute(
                    $relation->getMorphType(),
                    $identity instanceof Model ? $identity->getMorphClass() : $identity::class,
                );
                $factor->setAttribute($relation->getForeignKeyName(), $identity->getAuthIdentifier());
            }

            $factor->persist();
        } else {
            $this->assertFactorOwnership($factor, $identity);
        }

        $this->clearCache($identity);

        $events = $this->container->make(Dispatcher::class);
        $events->dispatch(new MfaFactorEnrolled($identity, $factor, $factor->getDriver()));
    }

    /**
     * Disable a previously-enrolled factor for the current identity.
     *
     * Deletes the underlying row when the factor is an Eloquent model,
     * invalidates the identity's setup-state cache so the next
     * `isSetup()` call reflects the removal, and dispatches
     * `MfaFactorDisabled` for downstream subscribers. Non-Eloquent
     * `Factor` implementations are left to the consumer to discard;
     * the event still fires so observers can react.
     *
     * Throws `FactorOwnershipMismatchException` when the supplied factor
     * does not belong to the current identity, preventing a caller from
     * deleting another account's factor by passing its identifier.
     *
     * No-op when no MFA-capable identity is resolvable, mirroring
     * `enrol()`'s shape.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @return void
     */
    public function disable(Factor $factor): void
    {
        $identity = $this->resolveIdentity();

        if ($identity === null) {
            return;
        }

        $this->assertFactorOwnership($factor, $identity);

        if ($factor instanceof Model) {
            $factor->delete();
        }

        $this->clearCache($identity);

        $events = $this->container->make(Dispatcher::class);
        $events->dispatch(new MfaFactorDisabled($identity, $factor, $factor->getDriver()));
    }

    /**
     * Issue a fresh batch of backup codes for the current identity.
     *
     * Atomically replaces the identity's existing `backup_code` factors
     * inside a single database transaction: every prior backup-code row
     * is deleted, a fresh batch is minted via the configured
     * `BackupCodeDriver`, and one `Factor` row per code is persisted
     * with the hashed value on `secret`. Returns the plaintext set
     * exactly once for the caller to display / download — the codes
     * are NEVER recoverable after this method returns, by design.
     *
     * Each new backup-code factor dispatches `MfaFactorEnrolled` so
     * audit subscribers see the rotation as a normal lifecycle event.
     * The identity's setup-state cache is invalidated so a subsequent
     * `isSetup()` reflects the new batch immediately.
     *
     * No-op (returns `[]`) when no MFA-capable identity is resolvable,
     * matching the established `enrol()` / `disable()` shape so
     * consumers can call this unconditionally without guarding against
     * unauthenticated requests.
     *
     * @param  ?int  $count
     * @return list<string>
     */
    public function issueBackupCodes(?int $count = null): array
    {
        $identity = $this->resolveIdentity();

        if ($identity === null) {
            return [];
        }

        $driver = $this->driver(BackupCodeDriver::NAME);

        if (!$driver instanceof BackupCodeDriver) {
            throw new \LogicException(sprintf('Driver [%s] must be a %s instance to issue backup codes.', BackupCodeDriver::NAME, BackupCodeDriver::class));
        }

        $codes = $driver->generateSet($count);

        $this->container->make(ConnectionInterface::class)->transaction(function () use ($identity, $driver, $codes): void {
            $this->rotateBackupCodeBatch($identity, $driver, $codes);
        });

        $this->clearCache($identity);

        return $codes;
    }

    /**
     * Resolve the named factor driver, narrowed to the `FactorDriver`
     * contract for downstream callers. The base manager's `driver()`
     * returns `mixed`; this helper locks the return type so callers
     * do not need to type-hint or assert at every site.
     *
     * @param  string  $name
     * @return \SineMacula\Laravel\Mfa\Contracts\FactorDriver
     */
    private function resolveDriver(string $name): FactorDriver
    {
        $instance = $this->driver($name);

        if (!$instance instanceof FactorDriver) {
            throw new \LogicException(sprintf('Driver [%s] must implement %s.', $name, FactorDriver::class));
        }

        return $instance;
    }

    /**
     * Persist the post-driver verification outcome on the factor row.
     *
     * Successful verification stamps `verified_at`, resets attempts,
     * and clears any pending OTP code; failure increments the attempt
     * counter and applies a per-driver lockout once the configured
     * threshold is crossed. Non-Eloquent factors carry no row to
     * mutate and skip both branches before this method is even called.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  string  $driver
     * @param  bool  $valid
     * @return void
     */
    private function applyVerificationOutcome(EloquentFactor $factor, string $driver, bool $valid): void
    {
        if ($valid) {
            $factor->recordVerification();
            $factor->persist();

            return;
        }

        $factor->recordAttempt();

        $maxAttempts = $this->resolveIntConfig('mfa.drivers.' . $driver . '.max_attempts', 0);

        if ($maxAttempts > 0 && $factor->getAttempts() >= $maxAttempts) {
            $factor->applyLockout(
                Carbon::now()->addMinutes($this->resolveIntConfig('mfa.lockout_minutes', 15)),
            );
        }

        $factor->persist();
    }

    /**
     * Apply the post-verify side effects: stamp the identity-level
     * verification through the bound store and dispatch `MfaVerified`
     * on success, or classify the failure and dispatch
     * `MfaVerificationFailed` with a machine-readable reason on
     * failure.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  string  $driver
     * @param  bool  $valid
     * @param  \Illuminate\Contracts\Events\Dispatcher  $events
     * @return void
     */
    private function finaliseVerification(
        MultiFactorAuthenticatable $identity,
        Factor $factor,
        string $driver,
        bool $valid,
        Dispatcher $events,
    ): void {
        if ($valid) {
            /** @var \SineMacula\Laravel\Mfa\Contracts\MfaVerificationStore $store */
            $store = $this->container->make(MfaVerificationStore::class);
            $store->markVerified($identity);
            $this->clearCache($identity);

            $events->dispatch(new MfaVerified($identity, $factor, $driver));

            return;
        }

        // Classify the failure inline. Branches in priority order:
        // - SecretMissing: TOTP enrolment never completed (no code AND no secret).
        // - CodeExpired:   pending OTP aged past its window.
        // - CodeMissing:   pending code exists but has no expiry — treat as missing.
        // - CodeInvalid:   default — TOTP window mismatch or OTP comparison mismatch.
        $expiresAt = $factor->getExpiresAt();
        $pending   = $factor->getCode();
        $secret    = $factor->getSecret();

        $reason = match (true) {
            $pending === null   && $secret === null     => MfaVerificationFailureReason::SecretMissing,
            $expiresAt !== null && $expiresAt->isPast() => MfaVerificationFailureReason::CodeExpired,
            $pending   !== null && $expiresAt === null  => MfaVerificationFailureReason::CodeMissing,
            default                                     => MfaVerificationFailureReason::CodeInvalid,
        };

        $events->dispatch(new MfaVerificationFailed($identity, $factor, $driver, $reason));
    }

    /**
     * Atomically replace the identity's existing backup-code factors
     * with the supplied freshly-minted batch. Runs inside a single
     * transaction provided by the caller — no overlap window where
     * both old and new codes would verify.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Drivers\BackupCodeDriver  $driver
     * @param  list<string>  $codes
     * @return void
     */
    private function rotateBackupCodeBatch(
        MultiFactorAuthenticatable $identity,
        BackupCodeDriver $driver,
        array $codes,
    ): void {
        $modelClass = $this->factorModel();
        $morphType  = $identity instanceof Model
            // @phpstan-ignore staticMethod.dynamicCall (getMorphClass is defined as an instance method upstream)
            ? $identity->getMorphClass()
            : $identity::class;
        $morphId = $identity->getAuthIdentifier();
        $events  = $this->container->make(Dispatcher::class);

        $modelClass::query()
            ->where('authenticatable_type', $morphType)
            ->where('authenticatable_id', $morphId)
            ->where('driver', BackupCodeDriver::NAME)
            ->delete();

        foreach ($codes as $code) {
            $factor   = new $modelClass;
            $relation = $factor->authenticatable();

            $factor->setAttribute($relation->getMorphType(), $morphType);
            $factor->setAttribute($relation->getForeignKeyName(), $morphId);
            $factor->setAttribute($factor->getDriverName(), BackupCodeDriver::NAME);
            $factor->setAttribute($factor->getSecretName(), $driver->hash($code));
            $factor->save();

            $events->dispatch(new MfaFactorEnrolled($identity, $factor, BackupCodeDriver::NAME));
        }
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
     * Verify that the given factor belongs to the supplied identity.
     *
     * Eloquent factors are matched by morph columns read directly off
     * the model attributes (no query triggered). Non-Eloquent factors
     * are matched by the `getAuthenticatable()` accessor — which the
     * contract guarantees does not lazy-load — comparing FQCN and
     * identifier. Either path throws `FactorOwnershipMismatchException`
     * on mismatch (or on a non-Eloquent factor whose owner is unknown).
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return void
     */
    private function assertFactorOwnership(
        Factor $factor,
        MultiFactorAuthenticatable $identity,
    ): void {
        // For the Eloquent-factor branch we compare against the identity's
        // `getMorphClass()` so consumers' `morphMap` configuration is
        // honoured — the string recorded on `authenticatable_type` matches
        // whatever the morph map resolves the identity to. The non-
        // Eloquent branch has no morph column to consult and falls back
        // to a strict FQCN comparison.
        $expectedType = $identity instanceof Model
            ? $identity->getMorphClass()
            : $identity::class;

        $expectedId = $identity->getAuthIdentifier();

        if ($factor instanceof EloquentFactor && $factor instanceof Model) {
            $relation   = $factor->authenticatable();
            $factorType = $factor->getAttribute($relation->getMorphType());
            $factorId   = $factor->getAttribute($relation->getForeignKeyName());
            $matches    = $factorType === $expectedType && $this->sameIdentifier($factorId, $expectedId);
        } else {
            $owner   = $factor->getAuthenticatable();
            $matches = $owner !== null
                && $owner::class === $identity::class
                && $this->sameIdentifier($owner->getAuthIdentifier(), $expectedId);
        }

        if (!$matches) {
            throw FactorOwnershipMismatchException::for($factor, $identity);
        }
    }

    /**
     * Compare two auth identifiers under the package's safe-cast rule:
     * both sides must be string|int, and their string representation
     * must match. Anything non-scalar collapses to `false` so the
     * ownership check fails closed rather than treating an unsupported
     * identifier shape as equal.
     *
     * @param  mixed  $left
     * @param  mixed  $right
     * @return bool
     */
    private function sameIdentifier(mixed $left, mixed $right): bool
    {
        if ((!is_string($left) && !is_int($left)) || (!is_string($right) && !is_int($right))) {
            return false;
        }

        return (string) $left === (string) $right;
    }

    /**
     * Resolve an integer setting from the application config.
     *
     * Two fallback values are accepted so callers can distinguish
     * "absent" (key missing → use a sensible default) from "malformed"
     * (key present but not coercible to int → fail safe by using
     * `$malformedFallback`, typically 0). The asymmetry is deliberate:
     * a misconfigured expiry value should not silently grant a long
     * valid window.
     *
     * @param  string  $key
     * @param  int  $default
     * @param  ?int  $malformedFallback
     * @return int
     */
    private function resolveIntConfig(
        string $key,
        int $default,
        ?int $malformedFallback = null,
    ): int {
        $config = $this->container->make('config');

        if (!$config->has($key)) {
            return $default;
        }

        /** @var mixed $value */
        $value = $config->get($key);

        // `is_numeric` is true for ints AND numeric-strings; the
        // subsequent `(int)` cast is identity for ints, so a single
        // arm covers both shapes without a redundant `is_int` branch.
        return is_numeric($value)
            ? (int) $value
            : ($malformedFallback ?? $default);
    }

    /**
     * Get the cache key prefix for the given identity.
     *
     * The prefix includes the identity's morph class (or FQCN for non-
     * Eloquent identities) so two MFA-capable models with overlapping
     * primary keys (`User #1` and `Admin #1`) cannot collide on a
     * single cache slot. Without that scope a multi-guard request
     * would let cached state from one identity bleed into the other.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $identity
     * @return string
     */
    private function getCachePrefix(Authenticatable $identity): string
    {
        $config = $this->container->make('config');

        /** @var string $prefix */
        $prefix = $config->get('mfa.cache_prefix', 'mfa:');

        $identifier = $identity->getAuthIdentifier();

        $suffix = is_string($identifier) || is_int($identifier)
            ? (string) $identifier
            : '';

        $class = $identity instanceof Model
            // @phpstan-ignore staticMethod.dynamicCall (getMorphClass is defined as an instance method upstream)
            ? $identity->getMorphClass()
            : $identity::class;

        return $prefix . $class . ':' . $suffix . ':';
    }
}
