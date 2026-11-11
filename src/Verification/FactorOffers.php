<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Verification;

use Carbon\CarbonInterface;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Applications\ApplicationSettings;
use SineMacula\Laravel\Mfa\Attempts\LockedFactors;
use SineMacula\Laravel\Mfa\Context\Caller;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Context\CallerContextResolver;
use SineMacula\Laravel\Mfa\Context\SessionFirstFactor;
use SineMacula\Laravel\Mfa\Contracts\ActiveStateResolver;
use SineMacula\Laravel\Mfa\Contracts\CombinationPolicy;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Database\WriteConnection;
use SineMacula\Laravel\Mfa\Drivers\DriverResolver;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Factors\FactorChannel;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyAssertions;
use SineMacula\Laravel\Mfa\Proofs\Proof;

/**
 * The factors a session is offered, leaving out any that cannot succeed. Offers
 * are advisory: sending and verifying repeat every check.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class FactorOffers
{
    /**
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContextResolver  $callers
     * @param  \SineMacula\Laravel\Mfa\Context\SessionFirstFactor  $firstFactors
     * @param  \SineMacula\Laravel\Mfa\Passkeys\PasskeyAssertions  $passkeys
     */
    public function __construct(

        /** Seams and configuration are resolved on every call. */
        private Container $container,

        /** Resolves who the request serves. */
        private CallerContextResolver $callers,

        /** Reads the session's first factor. */
        private SessionFirstFactor $firstFactors,

        /** Passkey ceremony checks. */
        private PasskeyAssertions $passkeys,
    ) {}

    /**
     * None for a request that serves nobody, an inactive identity or an unknown
     * first factor; a locked-out factor stays.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $context
     * @return list<\SineMacula\Laravel\Mfa\Factors\FactorSummary>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    public function offered(CallerContext $context): array
    {
        $caller = $this->callers->resolve($context, PendingAction::LIST_FACTORS);

        if ($caller === null || !$this->container->make(ActiveStateResolver::class)->isActive($caller->identity)) {
            return [];
        }

        $application = $this->callers->application($caller);
        $firstFactor = $this->firstFactor($caller, $application);

        if ($firstFactor === null) {
            return [];
        }

        $settings = new ApplicationSettings($this->container->make(Repository::class), $application);

        /** @var list<\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor> $factors */
        $factors = WriteConnection::query($caller->identity->authFactors())->get()->all();

        $offered = array_filter(
            $factors,
            fn (EloquentFactor&Model $factor): bool => $settings->enables($factor->getType()) && $this->canBeOffered($caller->identity, $application, $factor, $firstFactor),
        );

        usort($offered, static fn (EloquentFactor&Model $left, EloquentFactor&Model $right): int => self::rank($left) <=> self::rank($right));

        return array_map(FactorSummary::fromFactor(...), $offered);
    }

    /**
     * `null` when it is not known.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\Caller  $caller
     * @param  string  $application
     * @return ?\SineMacula\Laravel\Mfa\Proofs\Proof
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    private function firstFactor(Caller $caller, string $application): ?Proof
    {
        return $caller->pending === null
            ? $this->firstFactors->current($caller->identity, $application)
            : $this->firstFactors->ofPending($caller->identity, $caller->pending);
    }

    /**
     * Confirmed, not disabled, able to take part if a passkey, and accepted
     * after the first factor.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $firstFactor
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function canBeOffered(MultiFactorAuthenticatable $identity, string $application, EloquentFactor&Model $factor, Proof $firstFactor): bool
    {
        if (!$factor->isConfirmed() || $factor->getDisabledAt() !== null) {
            return false;
        }

        if ($factor->getType() === PasskeyAssertions::TYPE && !$this->passkeys->canTakePart($identity, $application, $factor)) {
            return false;
        }

        $driver  = $this->container->make(DriverResolver::class)->fromContainer($this->container, $factor->getType());
        $channel = FactorChannel::of($factor, $driver->channelKind());

        return $channel !== null && $this->container->make(CombinationPolicy::class)->accepts($firstFactor, $channel);
    }

    /**
     * Preferred first, then oldest, then by id.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @return array{0: bool, 1: int, 2: ?string}
     */
    private static function rank(EloquentFactor&Model $factor): array
    {
        $column  = $factor->getCreatedAtColumn();
        $created = $column === null ? null : $factor->getAttribute($column);

        return [!$factor->isPreferred(), $created instanceof CarbonInterface ? $created->getTimestamp() : 0, LockedFactors::idOf($factor)];
    }
}
