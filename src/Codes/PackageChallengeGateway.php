<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Codes;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Mfa\Attempts\ChallengeCounters;
use SineMacula\Laravel\Mfa\Attempts\ChallengeOutcome;
use SineMacula\Laravel\Mfa\Context\Caller;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Context\CallerContextResolver;
use SineMacula\Laravel\Mfa\Contracts\ChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\CodeDeliveryDriver;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Contracts\FactorDriver;
use SineMacula\Laravel\Mfa\Database\StorageTransaction;
use SineMacula\Laravel\Mfa\Drivers\DriverResolver;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Exceptions\UnsupportedFactorException;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;

/**
 * Default `ChallengeGateway` over the package's delivered codes. A binding must
 * match the caller's own exactly, so a pending credential never reaches a
 * sign-in in another application or session.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PackageChallengeGateway implements ChallengeGateway
{
    /**
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContextResolver  $callers
     * @param  \SineMacula\Laravel\Mfa\Attempts\ChallengeCounters  $counters
     * @param  \SineMacula\Laravel\Mfa\Codes\CodeService  $codes
     */
    public function __construct(

        /** Resolves drivers. */
        private Container $container,

        /** Caller resolver. */
        private CallerContextResolver $callers,

        /** Admits and records every challenge. */
        private ChallengeCounters $counters,

        /** Delivered codes. */
        private CodeService $codes,
    ) {}

    /**
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return \SineMacula\Laravel\Mfa\Codes\SendResult
     *
     * @throws \Throwable
     */
    #[\Override]
    public function send(CallerContext $caller, Factor $factor, ProofBinding $binding): SendResult
    {
        $served = $this->served($caller, self::actionOf($binding, PendingAction::SEND_CODE, PendingAction::START_BOOTSTRAP_ENROLLMENT), $binding);

        if ($served === null) {
            return SendResult::refused(FailureReason::NOT_FOUND);
        }

        $driver = $this->driver($factor);

        return StorageTransaction::run(function () use ($served, $factor, $binding, $driver): SendResult {

            $admission = $this->counters->isUsable($served->context(), $factor, $binding);

            return $admission->isAdmitted() ? $this->codes->send($served->identity, $factor, $binding, $driver) : SendResult::refusedBy($admission);
        });
    }

    /**
     * A challenge that is not admitted is refused without checking the code or
     * counting.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  string  $challengeId
     * @param  string  $code
     * @return \SineMacula\Laravel\Mfa\Attempts\ChallengeOutcome
     *
     * @throws \Throwable
     */
    #[\Override]
    public function verify(CallerContext $caller, Factor $factor, ProofBinding $binding, string $challengeId, #[\SensitiveParameter] string $code): ChallengeOutcome
    {
        $served = $this->served($caller, self::actionOf($binding, PendingAction::VERIFY, PendingAction::CONFIRM_BOOTSTRAP_ENROLLMENT), $binding);

        if ($served === null) {
            return ChallengeOutcome::refused(FailureReason::NOT_FOUND, 'The binding does not name the identity the caller is.');
        }

        return StorageTransaction::run(function () use ($served, $factor, $binding, $challengeId, $code): ChallengeOutcome {

            $admission = $this->counters->isUsable($served->context(), $factor, $binding);

            if (!$admission->isAdmitted()) {
                return ChallengeOutcome::refused($admission->reason ?? FailureReason::LOCKED, $admission->detail, $admission->lockedUntil);
            }

            $check   = $this->codes->check($factor, $binding, $code, $challengeId);
            $failure = $check->failure();
            $outcome = $this->counters->report($served->context(), $factor, $binding, $failure === null);

            return $failure === null && $outcome->passed
                ? ChallengeOutcome::passed()
                : ChallengeOutcome::failed($failure ?? FailureReason::INVALID_CODE, $check->detail());
        });
    }

    /**
     * The caller, when the binding matches its own exactly.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $context
     * @param  \SineMacula\Laravel\Mfa\Enums\PendingAction  $action
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return ?\SineMacula\Laravel\Mfa\Context\Caller
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    private function served(CallerContext $context, PendingAction $action, ProofBinding $binding): ?Caller
    {
        $caller = $this->callers->resolve($context, $action);

        if ($caller === null) {
            return null;
        }

        return $this->callers->binding($caller, $binding->purpose)?->toArray() === $binding->toArray() ? $caller : null;
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  \SineMacula\Laravel\Mfa\Enums\PendingAction  $action
     * @param  \SineMacula\Laravel\Mfa\Enums\PendingAction  $enrolling
     * @return \SineMacula\Laravel\Mfa\Enums\PendingAction
     */
    private static function actionOf(ProofBinding $binding, PendingAction $action, PendingAction $enrolling): PendingAction
    {
        return $binding->purpose === Purpose::ENROLLMENT ? $enrolling : $action;
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @return \SineMacula\Laravel\Mfa\Contracts\CodeDeliveryDriver
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedFactorException
     */
    private function driver(Factor $factor): CodeDeliveryDriver
    {
        return self::deliveringCodes($this->container->make(DriverResolver::class)->fromContainer($this->container, $factor->getType()), $factor->getType());
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\FactorDriver  $driver
     * @param  string  $type
     * @return \SineMacula\Laravel\Mfa\Contracts\CodeDeliveryDriver
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedFactorException
     */
    private static function deliveringCodes(FactorDriver $driver, string $type): CodeDeliveryDriver
    {
        if (!$driver instanceof CodeDeliveryDriver) {
            throw new UnsupportedFactorException(sprintf('The factor\'s type [%s] does not deliver codes.', $type));
        }

        return $driver;
    }
}
