<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Attempts;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Database\ConfiguredModels;
use SineMacula\Laravel\Mfa\Enums\AttemptScope;
use SineMacula\Laravel\Mfa\Events\Actor;
use SineMacula\Laravel\Mfa\Events\EventDispatcher;
use SineMacula\Laravel\Mfa\Events\FactorDisabled;
use SineMacula\Laravel\Mfa\Events\LockoutApplied;
use SineMacula\Laravel\Mfa\Events\LockoutLifted;
use SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use SineMacula\Laravel\Mfa\Models\IdentityState;
use SineMacula\Laravel\Mfa\Support\CurrentIdentity;
use SineMacula\Laravel\Mfa\Support\FactorStateTransaction;

/**
 * Counts failed attempts, applies and lifts lockouts, and disables a factor at
 * the failure ceiling.
 *
 * An attempt is counted against three scopes:
 *
 * - the factor, durably: its failures in a row (`consecutive_failures` on the
 *   factor's row), reset only by a success of that factor. From the factor
 *   limit on, each failure locks the factor for the lockout period; at the
 *   failure ceiling it is disabled until another factor is proved, it is
 *   rebound or the identity is reset;
 * - the identity, across all its factors and recovery codes: its failures
 *   within the window (a throttle row) lock it for the lockout period when they
 *   reach the identity limit (`locked_until` on its state row), and its durable
 *   run of failures (`consecutive_failures` on its state row) is reset only by
 *   a success or a reset. From the failure ceiling on, a failure disables the
 *   factor it was made against, and an attempt that names no factor of its own
 *   (a recovery code, a factor that keeps no state) is refused;
 * - the IP address, within the window, refused until the window ends once it
 *   reaches the IP limit.
 *
 * The identity's lockout, the factor's lockout and whether it is disabled are
 * read, the driver is called and the outcome is counted in one factor state
 * transaction, holding the identity's state lock (see
 * `FactorStateTransaction`), so parallel guesses for one identity are counted
 * one after the other and cannot overrun a cap. The verification is handed the
 * factor as stored under that lock, and an attempt on a factor that is not
 * among the identity's stored factors is answered as not found without calling
 * it. The IP address's slot is taken before, in one statement, and given back
 * unless the attempt fails, so parallel guesses from one address cannot
 * overrun its cap either. A refused attempt is counted nowhere and so extends
 * nothing; a success lifts no lockout and resets no other factor's count, and
 * sending a code resets nothing.
 *
 * Events are dispatched once the transaction has committed, so a listener that
 * throws cannot undo what was counted.
 *
 * `lockout()`, `liftLockout()`, `enableFactor()` and `resetIdentityFailures()`
 * are the operations an application builds unlocking, rebinding and resetting
 * on; `attempt()` is made by the package's own verification paths.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final readonly class AttemptService
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  \SineMacula\Laravel\Mfa\Attempts\AttemptStore  $store
     * @param  \SineMacula\Laravel\Mfa\Attempts\AttemptKeys  $keys
     * @param  \SineMacula\Laravel\Mfa\Attempts\IpThrottle  $ipThrottle
     * @param  \SineMacula\Laravel\Mfa\Events\EventDispatcher  $events
     */
    public function __construct(

        /** Configuration the attempt settings and the factor model are read from on every call. */
        private Repository $config,

        /** The throttle rows. */
        private AttemptStore $store,

        /** The keys the throttle rows are stored under. */
        private AttemptKeys $keys,

        /** The throttle on the IP address an attempt came from. */
        private IpThrottle $ipThrottle,

        /** The dispatcher of the lockout and failure ceiling events. */
        private EventDispatcher $events,
    ) {}

    /**
     * Make the attempt: refuse it while a lockout applies, otherwise run the
     * verification and count its outcome, all under the identity's factor state
     * lock.
     *
     * The verification runs inside the transaction and is handed the factor as
     * stored under the lock (the attempt's own factor when it keeps no state,
     * `null` for a recovery code), so it checks against the stored factor, not
     * what the caller read before, and whatever it writes (a TOTP step, a
     * delivered code used up, the factor's last use) commits with the count. A
     * verification that throws counts nothing.
     *
     * @param  \SineMacula\Laravel\Mfa\Attempts\Attempt  $attempt
     * @param  \Closure(?\SineMacula\Laravel\Mfa\Contracts\Factor): bool  $verify
     * @return \SineMacula\Laravel\Mfa\Attempts\AttemptOutcome
     *
     * @throws \Throwable
     *
     * @param-immediately-invoked-callable $verify
     *
     * @internal
     */
    public function attempt(Attempt $attempt, \Closure $verify): AttemptOutcome
    {
        $settings = new AttemptSettings($this->config);
        $slot     = $this->ipThrottle->take($attempt->ip, $settings);

        if ($slot instanceof Lockout) {
            return AttemptOutcome::refuse($slot);
        }

        /** @var list<\SineMacula\Laravel\Mfa\Contracts\MfaEvent> $events */
        $events = [];

        try {
            $outcome = FactorStateTransaction::forIdentity(
                $attempt->identity,
                $this->factorModel($attempt->factor),
                function (Collection $factors) use ($attempt, $verify, $settings, &$events): AttemptOutcome {

                    $events = [];

                    return $this->decide($attempt, $factors, $verify, $settings, $events);
                },
            );
        } catch (\Throwable $exception) {

            $this->ipThrottle->giveBack($slot);

            throw $exception;
        }

        if (!$outcome->isFailed()) {
            $this->ipThrottle->giveBack($slot);
        }

        foreach ($events as $event) {
            $this->events->dispatch($event);
        }

        return $outcome;
    }

    /**
     * The lockout an attempt by the identity, against the factor and from the
     * IP address, would be refused by now, or `null` when none applies: with no
     * factor, or one that keeps no state, that includes the identity's run at
     * the failure ceiling. It reads the write connection but takes no lock, so
     * it answers for this moment only; `attempt()` reads it again under the
     * lock.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  ?\SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  ?string  $ip
     * @return ?\SineMacula\Laravel\Mfa\Attempts\Lockout
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     *
     * @phpstan-impure
     */
    public function lockout(MultiFactorAuthenticatable $identity, ?Factor $factor = null, ?string $ip = null): ?Lockout
    {
        $now      = CarbonImmutable::now();
        $settings = new AttemptSettings($this->config);
        $state    = $this->identityState($this->subject($identity));
        $stored   = $this->storedFactor($factor);

        return Lockout::strictest(
            $stored === null ? $this->identityCeiling($state, $settings) : null,
            $this->identityLockout($state, $now),
            $this->factorLockout($stored, $now),
            $this->ipThrottle->lockout($ip, $settings, $now),
        );
    }

    /**
     * Lift the factor's lockout, or the identity's when no factor is given,
     * before it ends, as an action taken by the actor or by the identity
     * itself. The factor's failures in a row, and the identity's run, are
     * kept, since only a success resets them, so the next failure locks again;
     * a factor disabled at the failure ceiling stays disabled (see
     * `enableFactor()`). A factor that is not among the identity's stored
     * factors lifts nothing. Returns whether a live lockout was lifted, and
     * reports it when one was.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  ?\SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  ?\SineMacula\Laravel\Mfa\Events\Actor  $actor
     * @param  ?string  $application
     * @return bool
     *
     * @throws \Throwable
     *
     * @imperative
     */
    public function liftLockout(MultiFactorAuthenticatable $identity, ?Factor $factor = null, ?Actor $actor = null, ?string $application = null): bool
    {
        $subject = $this->subject($identity);

        $lifted = FactorStateTransaction::forIdentity($identity, $this->factorModel($factor), function (Collection $factors) use ($subject, $factor): bool {

            if ($factor === null) {

                $this->store->forget($this->keys->identity($subject[0], $subject[1]));

                return $this->unlockIdentity($subject);
            }

            $locked = LockedFactors::find($factor, $factors);
            $key    = $locked === null ? null : $this->factorKey($locked);

            if ($key === null) {
                return false;
            }

            $live = ($this->store->read([$key])[$key]['ends'] ?? 0) > CarbonImmutable::now()->getTimestamp();

            $this->store->forget($key);

            return $live;
        });

        if ($lifted) {
            $this->events->dispatch(new LockoutLifted(
                $this->events->context($identity, $application),
                $factor === null ? null : FactorSummary::fromFactor($factor),
                $actor,
            ));
        }

        return $lifted;
    }

    /**
     * Enable a factor the failure ceiling disabled, with its failures in a row
     * cleared: the step a rebind or a reset takes. A lockout of the factor is
     * left as it is (see `liftLockout()`). Returns whether the factor was
     * disabled.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @return bool
     *
     * @throws \Throwable
     *
     * @imperative
     */
    public function enableFactor(EloquentFactor&Model $factor): bool
    {
        return FactorStateTransaction::forFactor($factor, function (Collection $factors) use ($factor): bool {

            $locked = LockedFactors::find($factor, $factors);

            if ($locked === null || $locked->getDisabledAt() === null) {
                return false;
            }

            $this->enable($locked);

            return true;
        });
    }

    /**
     * Reset the identity's run of failures across its factors and recovery
     * codes: the step a reset of the identity takes, after which an attempt
     * that names no factor of its own is no longer refused at the failure
     * ceiling. No lockout is lifted, no factor is enabled and no factor's own
     * failures in a row are reset. Returns whether there was a run to reset.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return bool
     *
     * @throws \Throwable
     *
     * @imperative
     */
    public function resetIdentityFailures(MultiFactorAuthenticatable $identity): bool
    {
        $subject = $this->subject($identity);

        return FactorStateTransaction::forIdentity($identity, $this->factorModel(null), function () use ($subject): bool {

            $state = $this->identityState($subject, true);

            if ($state === null || $state->consecutive_failures === 0) {
                return false;
            }

            $state->consecutive_failures = 0;

            $state->save();

            return true;
        });
    }

    /**
     * Under the lock: answer an attempt on a factor that is not among the
     * identity's stored factors as not found, refuse the attempt while a
     * lockout applies, otherwise run the verification on the factor as stored
     * and count its outcome. The events to dispatch once the transaction has
     * committed are added to `$events`.
     *
     * @formatter:off
     *
     * @param  \SineMacula\Laravel\Mfa\Attempts\Attempt  $attempt
     * @param  \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>  $factors
     * @param  \Closure(?\SineMacula\Laravel\Mfa\Contracts\Factor): bool  $verify
     * @param  \SineMacula\Laravel\Mfa\Attempts\AttemptSettings  $settings
     * @param  list<\SineMacula\Laravel\Mfa\Contracts\MfaEvent>  $events
     * @return \SineMacula\Laravel\Mfa\Attempts\AttemptOutcome
     *
     * @formatter:on
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    private function decide(Attempt $attempt, Collection $factors, \Closure $verify, AttemptSettings $settings, array &$events): AttemptOutcome
    {
        $factor = LockedFactors::find($attempt->factor, $factors);

        if ($factor === null && LockedFactors::keepsState($attempt->factor)) {
            return AttemptOutcome::notFound();
        }

        $now     = CarbonImmutable::now();
        $subject = $this->subject($attempt->identity);
        $state   = $this->identityState($subject, true);

        $lockout = Lockout::strictest(
            $factor === null ? $this->identityCeiling($state, $settings) : null,
            $this->identityLockout($state, $now),
            $this->factorLockout($factor, $now),
        );

        if ($lockout !== null) {
            return AttemptOutcome::refuse($lockout);
        }

        if ($verify($factor ?? $attempt->factor) === true) {

            $this->countSuccess($state, $factor, $factors);

            return AttemptOutcome::pass();
        }

        $run = $this->countIdentityFailure($attempt, $subject, $state, $settings, $now, $events);

        if ($factor !== null) {
            $this->countFactorFailure($attempt, $factor, $settings, $now, $run >= $settings->failureCeiling(), $events);
        }

        return AttemptOutcome::fail();
    }

    /**
     * Count a success: the factor's failures in a row and the identity's run
     * are reset, and the identity's other factors the failure ceiling disabled
     * are enabled, since the person has proved another factor, with their
     * failures in a row kept. No lockout is lifted and no other factor's count
     * is reset.
     *
     * @formatter:off
     *
     * @param  ?\SineMacula\Laravel\Mfa\Models\IdentityState  $state
     * @param  (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor)|null  $factor
     * @param  \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>  $factors
     * @return void
     *
     * @formatter:on
     */
    private function countSuccess(?IdentityState $state, (EloquentFactor&Model)|null $factor, Collection $factors): void
    {
        if ($state !== null && $state->consecutive_failures !== 0) {

            $state->consecutive_failures = 0;

            $state->save();
        }

        if ($factor === null) {
            return;
        }

        if ($factor->getConsecutiveFailures() !== 0) {

            $factor->setAttribute($factor->getConsecutiveFailuresName(), 0);

            $factor->persist();
        }

        $proved = LockedFactors::idOf($factor);

        foreach ($factors as $other) {

            if (LockedFactors::idOf($other) === $proved || $other->getDisabledAt() === null) {
                continue;
            }

            $other->setAttribute($other->getDisabledAtName(), null);

            $other->persist();
        }
    }

    /**
     * Count a failure against the identity: its durable run, and its count
     * within the window, which locks it for the lockout period from the
     * identity limit on. Returns the run, counting this failure.
     *
     * @param  \SineMacula\Laravel\Mfa\Attempts\Attempt  $attempt
     * @param  array{0: string, 1: string}  $subject
     * @param  ?\SineMacula\Laravel\Mfa\Models\IdentityState  $state
     * @param  \SineMacula\Laravel\Mfa\Attempts\AttemptSettings  $settings
     * @param  \Carbon\CarbonImmutable  $now
     * @param  list<\SineMacula\Laravel\Mfa\Contracts\MfaEvent>  $events
     * @return int
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    private function countIdentityFailure(Attempt $attempt, array $subject, ?IdentityState $state, AttemptSettings $settings, CarbonImmutable $now, array &$events): int
    {
        $key = $this->keys->identity($subject[0], $subject[1]);

        $this->store->record($key, AttemptScope::IDENTITY, $now->getTimestamp(), $now->getTimestamp() + $settings->windowSeconds());

        if ($state === null) {
            return 0;
        }

        $state->consecutive_failures++;

        if (($this->store->read([$key])[$key]['hits'] ?? 0) < $settings->identityLimit()) {

            $state->save();

            return $state->consecutive_failures;
        }

        $until = $now->addSeconds($settings->lockoutSeconds());

        $state->locked_until = $until;

        $state->save();

        $events[] = new LockoutApplied($this->events->context($attempt->identity, $attempt->application), null, $until, $attempt->purpose);

        return $state->consecutive_failures;
    }

    /**
     * Count a failure against the factor: its failures in a row, which disable
     * it at the failure ceiling, as does a failure that brings the identity's
     * run to it, and otherwise lock it for the lockout period from the factor
     * limit on.
     *
     * @param  \SineMacula\Laravel\Mfa\Attempts\Attempt  $attempt
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  \SineMacula\Laravel\Mfa\Attempts\AttemptSettings  $settings
     * @param  \Carbon\CarbonImmutable  $now
     * @param  bool  $identityAtCeiling
     * @param  list<\SineMacula\Laravel\Mfa\Contracts\MfaEvent>  $events
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    private function countFactorFailure(
        Attempt $attempt,
        EloquentFactor&Model $factor,
        AttemptSettings $settings,
        CarbonImmutable $now,
        bool $identityAtCeiling,
        array &$events,
    ): void {
        $run = $factor->getConsecutiveFailures() + 1;

        $factor->setAttribute($factor->getConsecutiveFailuresName(), $run);

        if ($identityAtCeiling || $run >= $settings->failureCeiling()) {

            $factor->setAttribute($factor->getDisabledAtName(), $now);
            $factor->persist();

            $events[] = new FactorDisabled($this->events->context($attempt->identity, $attempt->application), FactorSummary::fromFactor($factor), $attempt->purpose);

            return;
        }

        $factor->persist();

        $key = $this->factorKey($factor);

        if ($key === null || $run < $settings->factorLimit()) {
            return;
        }

        $until = $now->addSeconds($settings->lockoutSeconds());

        $this->store->hold($key, AttemptScope::FACTOR, $run, $until->getTimestamp());

        $context = $this->events->context($attempt->identity, $attempt->application);

        $events[] = new LockoutApplied($context, FactorSummary::fromFactor($factor), $until, $attempt->purpose);
    }

    /**
     * Enable a factor the failure ceiling disabled, with its failures in a row
     * cleared.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @return void
     */
    private function enable(EloquentFactor&Model $factor): void
    {
        $factor->setAttribute($factor->getDisabledAtName(), null);
        $factor->setAttribute($factor->getConsecutiveFailuresName(), 0);

        $factor->persist();
    }

    /**
     * Clear the identity's lockout. Returns whether it was live.
     *
     * @param  array{0: string, 1: string}  $subject
     * @return bool
     *
     * @imperative
     */
    private function unlockIdentity(array $subject): bool
    {
        $state = $this->identityState($subject, true);
        $until = $state?->locked_until;

        if ($state === null || $until === null) {
            return false;
        }

        $state->locked_until = null;

        $state->save();

        return $until->isFuture();
    }

    /**
     * The identity's lockout, while it is live.
     *
     * @param  ?\SineMacula\Laravel\Mfa\Models\IdentityState  $state
     * @param  \Carbon\CarbonImmutable  $now
     * @return ?\SineMacula\Laravel\Mfa\Attempts\Lockout
     */
    private function identityLockout(?IdentityState $state, CarbonImmutable $now): ?Lockout
    {
        $until = $state?->locked_until;

        return $until !== null && $until->getTimestamp() > $now->getTimestamp()
            ? Lockout::endingAt(AttemptScope::IDENTITY, CarbonImmutable::instance($until))
            : null;
    }

    /**
     * The identity's run of failures at the failure ceiling, which refuses an
     * attempt that names no factor of its own.
     *
     * @param  ?\SineMacula\Laravel\Mfa\Models\IdentityState  $state
     * @param  \SineMacula\Laravel\Mfa\Attempts\AttemptSettings  $settings
     * @return ?\SineMacula\Laravel\Mfa\Attempts\Lockout
     *
     * @throws \InvalidArgumentException
     */
    private function identityCeiling(?IdentityState $state, AttemptSettings $settings): ?Lockout
    {
        return $state !== null && $state->consecutive_failures >= $settings->failureCeiling() ? Lockout::disabled(AttemptScope::IDENTITY) : null;
    }

    /**
     * The factor's lockout: disabled at the failure ceiling, or locked by its
     * failures in a row while that lockout is live.
     *
     * @param  (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor)|null  $factor
     * @param  \Carbon\CarbonImmutable  $now
     * @return ?\SineMacula\Laravel\Mfa\Attempts\Lockout
     *
     * @throws \InvalidArgumentException
     */
    private function factorLockout((EloquentFactor&Model)|null $factor, CarbonImmutable $now): ?Lockout
    {
        if ($factor === null) {
            return null;
        }

        if ($factor->getDisabledAt() !== null) {
            return Lockout::disabled();
        }

        $key  = $this->factorKey($factor);
        $ends = $key === null ? null : ($this->store->read([$key])[$key]['ends'] ?? null);

        return $ends !== null && $ends > $now->getTimestamp() ? Lockout::endingAtTimestamp(AttemptScope::FACTOR, $ends) : null;
    }

    /**
     * The identity's state row, read from the write connection, or `null` when
     * it has none yet. Under the factor state lock it is read with a locking
     * read, which this transaction already holds: on MySQL a plain read could
     * be answered from a snapshot an enclosing transaction took before the lock
     * was granted, and miss a lockout committed in the meantime.
     *
     * @param  array{0: string, 1: string}  $subject
     * @param  bool  $locked
     * @return ?\SineMacula\Laravel\Mfa\Models\IdentityState
     */
    private function identityState(array $subject, bool $locked = false): ?IdentityState
    {
        $query = IdentityState::query()
            ->useWritePdo()
            ->where('authenticatable_type', $subject[0])
            ->where('authenticatable_id', $subject[1]);

        return ($locked ? $query->lockForUpdate() : $query)->first();
    }

    /**
     * The factor as stored, read from the write connection, or `null` when it
     * keeps no state of its own or is gone.
     *
     * @param  ?\SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @return (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor)|null
     */
    private function storedFactor(?Factor $factor): (EloquentFactor&Model)|null
    {
        if (!LockedFactors::keepsState($factor)) {
            return null;
        }

        /** @var (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor)|null */
        return $factor->newQuery()->useWritePdo()->whereKey($factor->getKey())->first();
    }

    /**
     * The factor model the transaction locks the identity's factors through:
     * the factor's own when it is one, otherwise the configured model.
     *
     * @param  ?\SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\InvalidModelException
     */
    private function factorModel(?Factor $factor): EloquentFactor&Model
    {
        if (LockedFactors::keepsState($factor)) {
            return $factor;
        }

        $model = ConfiguredModels::factor($this->config);

        return new $model;
    }

    /**
     * The key of the factor's throttle row, or `null` for a factor without a
     * usable id.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    private function factorKey(Factor $factor): ?string
    {
        $id = LockedFactors::idOf($factor);

        return $id === null ? null : $this->keys->factor($id);
    }

    /**
     * The identity's owner type and key, as its rows are stored under.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return array{0: string, 1: string}
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    private function subject(MultiFactorAuthenticatable $identity): array
    {
        $key = $identity->getAuthIdentifier();

        if ((!is_string($key) && !is_int($key)) || $key === '') {
            throw new UnsupportedIdentifierException(sprintf('An identity key must be a non-empty string or an integer to count its attempts; got [%s].', get_debug_type($key)));
        }

        return [CurrentIdentity::typeOf($identity), (string) $key];
    }
}
