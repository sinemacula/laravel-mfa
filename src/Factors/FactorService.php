<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Factors;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Collection as BaseCollection;
use SineMacula\Laravel\Mfa\Applications\ApplicationSettings;
use SineMacula\Laravel\Mfa\Attempts\LockedFactors;
use SineMacula\Laravel\Mfa\Context\Caller;
use SineMacula\Laravel\Mfa\Context\CallerContextResolver;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Database\ConfiguredModels;
use SineMacula\Laravel\Mfa\Database\WriteConnection;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Events\EventDispatcher;
use SineMacula\Laravel\Mfa\Events\FactorRenamed;
use SineMacula\Laravel\Mfa\Events\PreferredFactorChanged;
use SineMacula\Laravel\Mfa\Support\FactorStateTransaction;

/**
 * Reads the current identity's factors and resolves the configured factor
 * model, and changes what a person says about a factor: its label and whether
 * it is the preferred one. Neither changes what the factor proves, so neither
 * needs a step-up; both serve active sessions only, under the identity's factor
 * state lock, and are reported once they commit.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class FactorService
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The container the configuration is read from. */
        private Container $container,
    ) {}

    /**
     * Determine whether the signed-in person has at least one registered
     * authentication factor; `false` on a pending session, and without an
     * MFA-capable person (see `Context\CallerContextResolver`).
     *
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function isSetup(): bool
    {
        $identity = $this->container->make(CallerContextResolver::class)->resolve(null)?->identity;

        if ($identity === null) {
            return false;
        }

        return $identity->isMfaEnabled();
    }

    /**
     * Get the authentication factors of the identity the request serves for
     * listing factors (see `Context\CallerContextResolver`): a pending
     * session's when its credential allows listing them, otherwise the
     * signed-in person's.
     *
     * Returns null when the request serves nobody for listing factors: a
     * pending session that does not allow it, no MFA-capable identity, or one
     * that is not a person. The factors are read from the write connection (see
     * `Database\WriteConnection`), as they decide verification and lockout, and
     * on every call, so nothing is kept from one request to the next.
     *
     * @formatter:off
     *
     * @return ?\Illuminate\Support\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\Factor>
     *
     * @formatter:on
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function getFactors(): ?BaseCollection
    {
        $caller = $this->container->make(CallerContextResolver::class)->resolve(PendingAction::LIST_FACTORS);

        if ($caller === null) {
            return null;
        }

        return WriteConnection::query($caller->identity->authFactors())->get()->toBase();
    }

    /**
     * Give a factor enrolled through the current application a new label: the
     * label is what that application shows, so another application's factor is
     * `not_found`, as one that is not the person's is.
     *
     * @param  mixed  $factorId
     * @param  ?string  $label
     * @return \SineMacula\Laravel\Mfa\Factors\FactorChange
     *
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    public function rename(mixed $factorId, ?string $label): FactorChange
    {
        $label  = FactorLabel::normalize($label);
        $caller = $this->served();

        if ($caller instanceof FactorChange) {
            return $caller;
        }

        return FactorStateTransaction::forIdentity(
            $caller->identity,
            new ($this->factorModel()),
            fn (Collection $factors): FactorChange => $this->renameUnderLock($caller, self::found($factorId, $factors), $label),
        );
    }

    /**
     * Make a confirmed factor, of a type the current application enables, the
     * identity's preferred one, which is offered first. The flag is the
     * identity's choice, kept on its factors' rows, so any other factor holding
     * it gives it up, through whichever application it was enrolled. Choosing
     * the factor already preferred changes nothing and reports nothing.
     *
     * @param  mixed  $factorId
     * @return \SineMacula\Laravel\Mfa\Factors\FactorChange
     *
     * @throws \Throwable
     */
    public function setPreferred(mixed $factorId): FactorChange
    {
        $caller = $this->served();

        if ($caller instanceof FactorChange) {
            return $caller;
        }

        return FactorStateTransaction::forIdentity(
            $caller->identity,
            new ($this->factorModel()),
            fn (Collection $factors): FactorChange => $this->preferUnderLock($caller, self::found($factorId, $factors), $factors),
        );
    }

    /**
     * Resolve the configured factor model class (see
     * `Database\ConfiguredModels`): the shipped `Factor` model unless
     * `mfa.factor.model` names another, which must extend Eloquent's model and
     * implement `EloquentFactor`.
     *
     * @return class-string<\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\InvalidModelException
     */
    public function factorModel(): string
    {
        return ConfiguredModels::factor($this->container->make('config'));
    }

    /**
     * The person a change is made for: one who is not served is `not_found`,
     * and an inactive one is refused.
     *
     * @return \SineMacula\Laravel\Mfa\Context\Caller|\SineMacula\Laravel\Mfa\Factors\FactorChange
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function served(): Caller|FactorChange
    {
        $caller = $this->container->make(CallerContextResolver::class)->resolve(null);

        return match (true) {
            $caller === null                  => FactorChange::refused(FailureReason::NOT_FOUND),
            !$caller->identity->isMfaActive() => FactorChange::refused(FailureReason::IDENTITY_INACTIVE),
            default                           => $caller,
        };
    }

    /**
     * Under the lock: refuse a factor that is not there or was enrolled through
     * another application, and give it the label.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\Caller  $caller
     * @param  (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor)|null  $factor
     * @param  ?string  $label
     * @return \SineMacula\Laravel\Mfa\Factors\FactorChange
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function renameUnderLock(Caller $caller, (EloquentFactor&Model)|null $factor, ?string $label): FactorChange
    {
        $application = $this->container->make(CallerContextResolver::class)->application($caller);

        if ($factor === null || $factor->getApplication() !== $application) {
            return FactorChange::refused(FailureReason::NOT_FOUND);
        }

        $previous = $factor->getLabel();

        $factor->setAttribute($factor->getLabelName(), $label);
        $factor->persist();

        $summary = FactorSummary::fromFactor($factor);
        $events  = $this->container->make(EventDispatcher::class);

        $events->dispatch(new FactorRenamed($events->context($caller->identity, $application), $summary, $previous));

        return FactorChange::made($summary);
    }

    /**
     * Under the lock: refuse a factor that is not there, not confirmed, or of a
     * type the application does not enable, then make it the preferred one.
     *
     * @formatter:off
     *
     * @param  \SineMacula\Laravel\Mfa\Context\Caller  $caller
     * @param  (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor)|null  $factor
     * @param  \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>  $factors
     * @return \SineMacula\Laravel\Mfa\Factors\FactorChange
     *
     * @formatter:on
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    private function preferUnderLock(Caller $caller, (EloquentFactor&Model)|null $factor, Collection $factors): FactorChange
    {
        $application = $this->container->make(CallerContextResolver::class)->application($caller);

        if ($factor === null || !$factor->isConfirmed()) {
            return FactorChange::refused(FailureReason::NOT_FOUND);
        }

        if (!(new ApplicationSettings($this->container->make(Repository::class), $application))->enables($factor->getType())) {
            return FactorChange::refused(FailureReason::TYPE_NOT_ENABLED);
        }

        return $factor->isPreferred() ? FactorChange::made(FactorSummary::fromFactor($factor)) : $this->prefer($caller, $application, $factor, $factors);
    }

    /**
     * Move the flag to the factor from whichever held it, and report the
     * change.
     *
     * @formatter:off
     *
     * @param  \SineMacula\Laravel\Mfa\Context\Caller  $caller
     * @param  string  $application
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>  $factors
     * @return \SineMacula\Laravel\Mfa\Factors\FactorChange
     *
     * @formatter:on
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function prefer(Caller $caller, string $application, EloquentFactor&Model $factor, Collection $factors): FactorChange
    {
        $previous = $factors->first(static fn (EloquentFactor&Model $other): bool => $other->isPreferred());
        $summary  = $previous === null ? null : FactorSummary::fromFactor($previous);

        $previous?->setAttribute($previous->getPreferredName(), false);
        $previous?->persist();

        $factor->setAttribute($factor->getPreferredName(), true);
        $factor->persist();

        $changed = FactorSummary::fromFactor($factor);
        $events  = $this->container->make(EventDispatcher::class);

        $events->dispatch(new PreferredFactorChanged($events->context($caller->identity, $application), $changed, $summary));

        return FactorChange::made($changed);
    }

    /**
     * The factor with the given id among those stored under the lock, or
     * `null`. An id that is neither a string nor an integer finds nothing.
     *
     * @formatter:off
     *
     * @param  mixed  $factorId
     * @param  \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>  $factors
     * @return (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor)|null
     *
     * @formatter:on
     */
    private static function found(mixed $factorId, Collection $factors): (EloquentFactor&Model)|null
    {
        if (!is_string($factorId) && !is_int($factorId)) {
            return null;
        }

        return $factors->first(static fn (EloquentFactor&Model $factor): bool => LockedFactors::idOf($factor) === (string) $factorId);
    }
}
