<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Requirements;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Collection;
use SineMacula\Laravel\Mfa\Contracts\FactorChangeGate;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Database\OpenTransaction;
use SineMacula\Laravel\Mfa\Enums\FactorChange;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;

/**
 * Asks the bound `FactorChangeGate` to authorise a change, the one way every
 * flow does: inside the identity's factor state transaction, with the
 * requirement the application configures for the change's operation, refusing a
 * grant whose authorisation has no end or has ended already. The gate's refusal
 * is reported as the package's own, since refusing by throwing is how the
 * contract answers.
 *
 * Stateless: the gate is resolved on every call.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class FactorChanges
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** The container the gate is resolved from on every call. */
        private Container $container,

        /** The configuration the operations' requirements are read from on every call. */
        private Repository $config,
    ) {}

    /**
     * Authorise a change that is a grant from the sign-in, on the factors as
     * stored under the lock, and say when the grant ends: refused when the gate
     * gives it no end, or one that is not in the future.
     *
     * @formatter:off
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $session
     * @param  \SineMacula\Laravel\Mfa\Enums\FactorChange  $change
     * @param  \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>  $factors
     * @return \Carbon\CarbonImmutable
     *
     * @formatter:on
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    public function grant(MultiFactorAuthenticatable $identity, string $application, string $session, FactorChange $change, Collection $factors): CarbonImmutable
    {
        self::assertGrant($change, true);

        $until = $this->ask(new FactorChangeRequest($identity, $application, $session, $change, $factors, null, $this->requirementFor($application, $change)));

        OperationRefusedException::byPackageUnless(
            $until !== null && $until->isFuture(),
            FailureReason::NOT_FRESH,
            sprintf('The authorisation of [%s] has no end in the future.', $change->value),
        );

        return $until;
    }

    /**
     * Authorise a change that is not a grant from the sign-in, on the factors
     * as stored under the lock.
     *
     * @formatter:off
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $session
     * @param  \SineMacula\Laravel\Mfa\Enums\FactorChange  $change
     * @param  \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>  $factors
     * @param  ?string  $factorId
     * @return void
     *
     * @formatter:on
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    public function allow(MultiFactorAuthenticatable $identity, string $application, string $session, FactorChange $change, Collection $factors, ?string $factorId = null): void
    {
        self::assertGrant($change, false);

        $this->ask(new FactorChangeRequest($identity, $application, $session, $change, $factors, $factorId, $this->requirementFor($application, $change)));
    }

    /**
     * The requirement the application configures for the change's operation, or
     * `null` with none, or for a change with no operation.
     *
     * @param  string  $application
     * @param  \SineMacula\Laravel\Mfa\Enums\FactorChange  $change
     * @return ?\SineMacula\Laravel\Mfa\Requirements\Requirement
     *
     * @throws \InvalidArgumentException
     */
    private function requirementFor(string $application, FactorChange $change): ?Requirement
    {
        $operation = $change->operation();

        return $operation === null ? null : (new OperationRequirements($this->config))->effective($application, $operation->value);
    }

    /**
     * Ask the bound gate, inside the identity's factor state transaction. A
     * bound gate of an application's or an adapter's refuses by throwing, as
     * the contract answers, so its refusal is reported as the package's own.
     * The package's default marks its own refusals itself, so a refusal a seam
     * it asks throws (the freshness gate's, say) propagates unmarked, as it
     * would from anywhere else.
     *
     * @param  \SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest  $request
     * @return ?\Carbon\CarbonImmutable
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    private function ask(FactorChangeRequest $request): ?CarbonImmutable
    {
        OpenTransaction::assertOpen('A factor change is authorised only inside the identity\'s factor state transaction.');

        $gate = $this->container->make(FactorChangeGate::class);

        try {
            return $gate->authorize($request);
        } catch (OperationRefusedException $refusal) {
            $marked = $refusal->byPackage || $gate instanceof ConfiguredFactorChangeGate;

            self::refuse($marked ? $refusal : OperationRefusedException::byPackage($refusal->reason, $refusal->getMessage()));
        }
    }

    /**
     * Refuse a change asked as a grant that is not one, or the reverse.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\FactorChange  $change
     * @param  bool  $grant
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function assertGrant(FactorChange $change, bool $grant): void
    {
        if ($change->isGrant() !== $grant) {
            throw new \InvalidArgumentException(sprintf('The change [%s] is %s.', $change->value, $grant ? 'not a grant' : 'a grant'));
        }
    }

    /**
     * Throw the refusal.
     *
     * @param  \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException  $refusal
     * @return never
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    private static function refuse(OperationRefusedException $refusal): never
    {
        throw $refusal;
    }
}
