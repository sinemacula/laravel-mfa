<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Factors;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Applications\ApplicationSettings;
use SineMacula\Laravel\Mfa\Attempts\LockedFactors;
use SineMacula\Laravel\Mfa\Context\Caller;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Context\CallerContextResolver;
use SineMacula\Laravel\Mfa\Contracts\ActiveStateResolver;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Database\ConfiguredModels;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Events\EventDispatcher;
use SineMacula\Laravel\Mfa\Events\FactorRenamed;
use SineMacula\Laravel\Mfa\Events\PreferredFactorChanged;
use SineMacula\Laravel\Mfa\Support\FactorStateTransaction;

/**
 * Lists factors and changes their label and preference. Neither change alters
 * what a factor proves, so neither needs a step-up.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class FactorService
{
    /**
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** Resolves the configuration and seams per call. */
        private Container $container,
    ) {}

    /**
     * Every factor of the identity, pending and other applications' included,
     * preferred first, then by id.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $context
     * @return list<\SineMacula\Laravel\Mfa\Factors\FactorSummary>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function factors(CallerContext $context): array
    {
        /** @var list<\SineMacula\Laravel\Mfa\Factors\FactorSummary> */
        return $this->listed($context)
            ->sortBy(static fn (EloquentFactor&Model $factor): array => [!$factor->isPreferred(), LockedFactors::idOf($factor)])
            ->map(static fn (EloquentFactor&Model $factor): FactorSummary => FactorSummary::fromFactor($factor))
            ->values()
            ->all();
    }

    /**
     * Null for another person's factor, as for one that does not exist.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $context
     * @param  mixed  $factorId
     * @return ?\SineMacula\Laravel\Mfa\Factors\FactorSummary
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function factor(CallerContext $context, mixed $factorId): ?FactorSummary
    {
        $factor = LockedFactors::withId($factorId, $this->listed($context));

        return $factor === null ? null : FactorSummary::fromFactor($factor);
    }

    /**
     * The label is what the enrolling application shows, so another
     * application's factor is `not_found`.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $context
     * @param  mixed  $factorId
     * @param  ?string  $label
     * @return \SineMacula\Laravel\Mfa\Factors\FactorChange
     *
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    public function rename(CallerContext $context, mixed $factorId, ?string $label): FactorChange
    {
        $label  = FactorLabel::normalize($label);
        $caller = $this->served($context);

        if ($caller instanceof FactorChange) {
            return $caller;
        }

        return FactorStateTransaction::forIdentity(
            $caller->identity,
            new ($this->factorModel()),
            fn (Collection $factors): FactorChange => $this->renameUnderLock($caller, LockedFactors::withId($factorId, $factors), $label),
        );
    }

    /**
     * The flag is the identity's choice across applications, so any other
     * factor holding it gives it up.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $context
     * @param  mixed  $factorId
     * @return \SineMacula\Laravel\Mfa\Factors\FactorChange
     *
     * @throws \Throwable
     */
    public function setPreferred(CallerContext $context, mixed $factorId): FactorChange
    {
        $caller = $this->served($context);

        if ($caller instanceof FactorChange) {
            return $caller;
        }

        return FactorStateTransaction::forIdentity(
            $caller->identity,
            new ($this->factorModel()),
            fn (Collection $factors): FactorChange => $this->preferUnderLock($caller, LockedFactors::withId($factorId, $factors), $factors),
        );
    }

    /**
     * @return class-string<\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\InvalidModelException
     */
    public function factorModel(): string
    {
        return ConfiguredModels::factor($this->container->make('config'));
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $context
     * @return \SineMacula\Laravel\Mfa\Context\Caller|\SineMacula\Laravel\Mfa\Factors\FactorChange
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function served(CallerContext $context): Caller|FactorChange
    {
        $caller = $this->container->make(CallerContextResolver::class)->resolve($context, null);
        $active = $this->container->make(ActiveStateResolver::class);

        return match (true) {
            $caller === null                      => FactorChange::refused(FailureReason::NOT_FOUND),
            !$active->isActive($caller->identity) => FactorChange::refused(FailureReason::IDENTITY_INACTIVE),
            default                               => $caller,
        };
    }

    /**
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

        $events->dispatch(new FactorRenamed($events->context($caller->identity, $application, $caller->client), $summary, $previous));

        return FactorChange::made($summary);
    }

    /**
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

        $events->dispatch(new PreferredFactorChanged($events->context($caller->identity, $application, $caller->client), $changed, $summary));

        return FactorChange::made($changed);
    }

    /**
     * @formatter:off
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $context
     * @return \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>
     *
     * @formatter:on
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function listed(CallerContext $context): Collection
    {
        $model  = new ($this->factorModel());
        $caller = $this->container->make(CallerContextResolver::class)->resolve($context, PendingAction::LIST_FACTORS);

        return $caller === null ? $model->newCollection() : FactorStateTransaction::snapshot($caller->identity, $model);
    }
}
