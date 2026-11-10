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
 * The factors a session is offered, as summaries: the identity's confirmed
 * factors, of a type the application enables, that the combination policy
 * accepts after the session's first factor, the preferred one first, then the
 * oldest, then by id; none while that first factor is not known.
 *
 * Left out, because they cannot succeed: a factor disabled at the failure
 * ceiling, and a passkey when the gateway is unavailable or its association or
 * credential is missing. A factor under a temporary lockout stays. A pending
 * session must allow listing factors; a request that serves nobody, and an
 * inactive identity, are offered nothing. Recovery codes are never offered.
 *
 * Offers are advisory: sending and verifying repeat every check.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class FactorOffers
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContextResolver  $callers
     * @param  \SineMacula\Laravel\Mfa\Context\SessionFirstFactor  $firstFactors
     * @param  \SineMacula\Laravel\Mfa\Passkeys\PasskeyAssertions  $passkeys
     */
    public function __construct(

        /** The container the configuration and the seams are resolved from. */
        private Container $container,

        /** The resolver of who the request serves. */
        private CallerContextResolver $callers,

        /** The reader of the session's first factor. */
        private SessionFirstFactor $firstFactors,

        /** The ceremony checks of a passkey. */
        private PasskeyAssertions $passkeys,
    ) {}

    /**
     * The factors offered to the session the request serves.
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
            fn (EloquentFactor&Model $factor): bool => $settings->enables($factor->getType()) && $this->canBeOffered($caller->identity, $factor, $firstFactor),
        );

        usort($offered, static fn (EloquentFactor&Model $left, EloquentFactor&Model $right): int => self::rank($left) <=> self::rank($right));

        return array_map(FactorSummary::fromFactor(...), $offered);
    }

    /**
     * The first factor of the session the request serves, or `null` when it is
     * not known.
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
     * Whether the factor could succeed on the session: confirmed, not disabled
     * at the failure ceiling, able to take part if it is a passkey, and
     * accepted after the first factor.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $firstFactor
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function canBeOffered(MultiFactorAuthenticatable $identity, EloquentFactor&Model $factor, Proof $firstFactor): bool
    {
        if (!$factor->isConfirmed() || $factor->getDisabledAt() !== null) {
            return false;
        }

        if ($factor->getType() === PasskeyAssertions::TYPE && !$this->passkeys->canTakePart($identity, $factor)) {
            return false;
        }

        $driver  = $this->container->make(DriverResolver::class)->fromContainer($this->container, $factor->getType());
        $channel = FactorChannel::of($factor, $driver->channelKind());

        return $channel !== null && $this->container->make(CombinationPolicy::class)->accepts($firstFactor, $channel);
    }

    /**
     * Where the factor falls in the list: the preferred one first, then the
     * oldest, then by id.
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
