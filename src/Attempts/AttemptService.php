<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Attempts;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Context\ClientContext;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Database\ConfiguredModels;
use SineMacula\Laravel\Mfa\Database\WriteConnection;
use SineMacula\Laravel\Mfa\Enums\AttemptScope;
use SineMacula\Laravel\Mfa\Events\Actor;
use SineMacula\Laravel\Mfa\Events\EventDispatcher;
use SineMacula\Laravel\Mfa\Events\FactorDisabled;
use SineMacula\Laravel\Mfa\Events\LockoutApplied;
use SineMacula\Laravel\Mfa\Events\LockoutLifted;
use SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException;
use SineMacula\Laravel\Mfa\Exceptions\WriteCanceledException;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use SineMacula\Laravel\Mfa\Models\IdentityState;
use SineMacula\Laravel\Mfa\Support\FactorStateTransaction;
use SineMacula\Laravel\Mfa\Support\IdentityType;

/**
 * Counts failures per factor, identity and IP address, applies lockouts and
 * disables a factor at the failure ceiling. Lockout checks, verification and
 * counting share one identity lock so parallel guesses cannot overrun a cap.
 * Events fire after commit so a throwing listener cannot undo a count.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final readonly class AttemptService
{
    /**
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  \SineMacula\Laravel\Mfa\Attempts\AttemptStore  $store
     * @param  \SineMacula\Laravel\Mfa\Attempts\AttemptKeys  $keys
     * @param  \SineMacula\Laravel\Mfa\Attempts\IpThrottle  $ipThrottle
     * @param  \SineMacula\Laravel\Mfa\Events\EventDispatcher  $events
     */
    public function __construct(

        /** Read on every call. */
        private Repository $config,

        /** Throttle rows. */
        private AttemptStore $store,

        /** Throttle row keys. */
        private AttemptKeys $keys,

        /** IP throttle. */
        private IpThrottle $ipThrottle,

        /** Lockout and failure ceiling events. */
        private EventDispatcher $events,
    ) {}

    /**
     * The verification gets the factor as locked, so its writes commit with the
     * count; one that throws counts nothing.
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

        /** @var list<\SineMacula\Laravel\Mfa\Contracts\MfaEvent> $events */
        $events = [];

        $outcome = FactorStateTransaction::forIdentity(
            $attempt->identity,
            $this->factorModel($attempt->factor),
            function (Collection $factors) use ($attempt, $verify, $settings, &$events): AttemptOutcome {

                $events = [];

                return $this->decide($attempt, $factors, $verify, $settings, $events);
            },
        );

        foreach ($events as $event) {
            $this->events->dispatch($event);
        }

        return $outcome;
    }

    /**
     * Hold an IP slot around the verification, outside any package transaction
     * so it survives a rollback; given back unless it failed.
     *
     * @param  ?string  $ip
     * @param  \Closure(): \SineMacula\Laravel\Mfa\Attempts\AttemptOutcome  $verification
     * @return \SineMacula\Laravel\Mfa\Attempts\AttemptOutcome
     *
     * @throws \Throwable
     *
     * @param-immediately-invoked-callable $verification
     *
     * @internal
     */
    public function throttled(?string $ip, \Closure $verification): AttemptOutcome
    {
        $slot = $this->ipThrottle->take($ip, new AttemptSettings($this->config));

        if ($slot instanceof Lockout) {
            return AttemptOutcome::refuse($slot);
        }

        try {
            $outcome = $verification();
        } catch (\Throwable $exception) {

            $this->ipThrottle->giveBack($slot);

            throw $exception;
        }

        if (!$outcome->isFailed()) {
            $this->ipThrottle->giveBack($slot);
        }

        return $outcome;
    }

    /**
     * Advisory: reads without a lock, so a caller's transaction may see an
     * older snapshot. `attempt()` reads again under the lock.
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
            $stored === null ? HeldLockouts::identityCeiling($state, $settings) : null,
            HeldLockouts::identity($state, $now),
            HeldLockouts::factor($stored, $now),
            $this->ipThrottle->lockout($ip, $settings, $now),
        );
    }

    /**
     * For a caller holding the factor state lock; ignores the IP address.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor)|null  $factor
     * @return ?\SineMacula\Laravel\Mfa\Attempts\Lockout
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     *
     * @internal
     */
    public function lockedOut(MultiFactorAuthenticatable $identity, (EloquentFactor&Model)|null $factor): ?Lockout
    {
        $state = $this->identityState($this->subject($identity), true);

        return HeldLockouts::strictest($state, $factor, new AttemptSettings($this->config), CarbonImmutable::now());
    }

    /**
     * Lift the factor's lockout, or the identity's when no factor is given.
     * Failure counts are kept, so the next failure locks again. `false` can
     * still mean the identity's throttle window was cleared.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  ?\SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  ?\SineMacula\Laravel\Mfa\Events\Actor  $actor
     * @param  ?string  $application
     * @param  ?\SineMacula\Laravel\Mfa\Context\ClientContext  $client
     * @return bool
     *
     * @throws \Throwable
     *
     * @imperative
     */
    public function liftLockout(
        MultiFactorAuthenticatable $identity,
        ?Factor $factor = null,
        ?Actor $actor = null,
        ?string $application = null,
        ?ClientContext $client = null,
    ): bool {
        $subject = $this->subject($identity);

        $lifted = FactorStateTransaction::forIdentity($identity, $this->factorModel($factor), function (Collection $factors) use ($subject, $factor): bool {

            if ($factor === null) {

                $this->store->forget($this->keys->identity($subject[0], $subject[1]));

                return $this->unlockIdentity($subject);
            }

            $locked = LockedFactors::find($factor, $factors);

            return $locked !== null && $this->unlockFactor($locked);
        });

        if ($lifted) {
            $this->events->dispatch(new LockoutLifted(
                $this->events->context($identity, $application, $client),
                $factor === null ? null : FactorSummary::fromFactor($factor),
                $actor,
            ));
        }

        return $lifted;
    }

    /**
     * Enable a factor the failure ceiling disabled and clear its failures; a
     * lockout is left in place. Returns whether it was disabled.
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

            $locked->setAttribute($locked->getDisabledAtName(), null);
            $locked->setAttribute($locked->getConsecutiveFailuresName(), 0);

            $locked->persist();

            return true;
        });
    }

    /**
     * Reset the identity's run of failures; lockouts and factor counts are
     * untouched. Returns whether there was a run to reset.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return bool
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\WriteCanceledException
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

            self::saveState($state, 'the identity\'s failures in a row');

            return true;
        });
    }

    /**
     * Events to dispatch after commit are appended to `$events`.
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
     * @throws \SineMacula\Laravel\Mfa\Exceptions\WriteCanceledException
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

        $lockout = HeldLockouts::strictest($state, $factor, $settings, $now);

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

        // Nothing held before counting, so anything held now was caused by it
        return AttemptOutcome::fail(HeldLockouts::strictest($state, $factor, $settings, $now));
    }

    /**
     * Proving one factor re-enables the identity's other disabled factors,
     * keeping their failure counts. No lockout is lifted.
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
     * Returns the identity's run including this failure.
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
     * @throws \SineMacula\Laravel\Mfa\Exceptions\WriteCanceledException
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

            self::saveState($state, 'the identity\'s failures in a row');

            return $state->consecutive_failures;
        }

        $until = $now->addSeconds($settings->lockoutSeconds());

        $state->locked_until = $until;

        self::saveState($state, 'the identity\'s lockout');

        $events[] = new LockoutApplied($this->events->context($attempt->identity, $attempt->application, $attempt->client), null, $until, $attempt->purpose);

        return $state->consecutive_failures;
    }

    /**
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

            $context  = $this->events->context($attempt->identity, $attempt->application, $attempt->client);
            $events[] = new FactorDisabled($context, FactorSummary::fromFactor($factor), $attempt->purpose);

            return;
        }

        if ($run < $settings->factorLimit()) {

            $factor->persist();

            return;
        }

        $until = $now->addSeconds($settings->lockoutSeconds());

        $factor->setAttribute($factor->getLockedUntilName(), $until);
        $factor->persist();

        $context = $this->events->context($attempt->identity, $attempt->application, $attempt->client);

        $events[] = new LockoutApplied($context, FactorSummary::fromFactor($factor), $until, $attempt->purpose);
    }

    /**
     * Clears an expired deadline too. Returns whether it was live.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @return bool
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\WriteCanceledException
     *
     * @imperative
     */
    private function unlockFactor(EloquentFactor&Model $factor): bool
    {
        $until = $factor->getLockedUntil();

        if ($until === null) {
            return false;
        }

        $factor->setAttribute($factor->getLockedUntilName(), null);
        $factor->persist();

        return $until->isFuture();
    }

    /**
     * Returns whether the lockout was live.
     *
     * @param  array{0: string, 1: string}  $subject
     * @return bool
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\WriteCanceledException
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

        self::saveState($state, 'the identity\'s lockout');

        return $until->isFuture();
    }

    /**
     * Throw when a model event cancels the save so the transaction rolls back.
     *
     * @param  \SineMacula\Laravel\Mfa\Models\IdentityState  $state
     * @param  string  $what
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\WriteCanceledException
     */
    private static function saveState(IdentityState $state, string $what): void
    {
        if (!$state->save()) {
            throw new WriteCanceledException(sprintf('A model event cancelled the save of %s.', $what));
        }
    }

    /**
     * Under the lock, read with `FOR UPDATE`: on MySQL a plain read may come
     * from an older snapshot and miss a lockout committed meanwhile.
     *
     * @param  array{0: string, 1: string}  $subject
     * @param  bool  $locked
     * @return ?\SineMacula\Laravel\Mfa\Models\IdentityState
     */
    private function identityState(array $subject, bool $locked = false): ?IdentityState
    {
        $query = WriteConnection::query(IdentityState::query())
            ->where('authenticatable_type', $subject[0])
            ->where('authenticatable_id', $subject[1]);

        return ($locked ? $query->lockForUpdate() : $query)->first();
    }

    /**
     * @param  ?\SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @return (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor)|null
     */
    private function storedFactor(?Factor $factor): (EloquentFactor&Model)|null
    {
        if (!LockedFactors::keepsState($factor)) {
            return null;
        }

        /** @var (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor)|null */
        return WriteConnection::query($factor->newQuery())->whereKey($factor->getKey())->first();
    }

    /**
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

        return [IdentityType::of($identity), (string) $key];
    }
}
