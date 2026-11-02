<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Codes;

use Illuminate\Contracts\Container\Container;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Mfa\Attempts\ChallengeCounters;
use SineMacula\Laravel\Mfa\Attempts\ChallengeOutcome;
use SineMacula\Laravel\Mfa\Context\CallerContextResolver;
use SineMacula\Laravel\Mfa\Contracts\ChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\CodeDeliveryDriver;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Contracts\FactorDriver;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Database\StorageConnection;
use SineMacula\Laravel\Mfa\Drivers\DriverResolver;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Exceptions\UnsupportedFactorException;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;

/**
 * The default `ChallengeGateway`: the package's own delivered codes (see
 * `CodeService`), owned exactly as an authentication layer must own its
 * challenges.
 *
 * Each call opens a transaction on the storage connection and asks
 * `Attempts\ChallengeCounters::isUsable()` first, so a locked or disabled
 * factor, a locked identity, a pending factor, a type the application does not
 * enable and a factor the combination policy does not accept after the
 * session's first factor are refused before anything is sent or checked.
 * Sending then issues and delivers a code bound as the binding says; verifying
 * checks the code against the named challenge, consuming it when it matches,
 * and reports the outcome through the counters in the same transaction. A
 * delivery is never reported. The caller is served only when the request's
 * pending session allows sending or verifying, or it has no pending session and
 * its signed-in person is served, and only for a binding that is exactly the
 * caller's own (see `Context\CallerContextResolver::binding()`): its identity,
 * its application, its session (the pending session's, or the current
 * sign-in's) and the binding's purpose. A binding of another application or
 * session of the same identity is refused, so a pending credential never
 * reaches an active sign-in elsewhere.
 *
 * Stateless: the request, the driver and the connection are resolved on every
 * call.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PackageChallengeGateway implements ChallengeGateway
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContextResolver  $callers
     * @param  \SineMacula\Laravel\Mfa\Attempts\ChallengeCounters  $counters
     * @param  \SineMacula\Laravel\Mfa\Codes\CodeService  $codes
     */
    public function __construct(

        /** The container the drivers are resolved from. */
        private Container $container,

        /** The resolver of who the request serves. */
        private CallerContextResolver $callers,

        /** The counts every challenge is admitted and reported through. */
        private ChallengeCounters $counters,

        /** The package's own delivered codes. */
        private CodeService $codes,
    ) {}

    /**
     * Send a code for the factor, bound as the binding says: the challenge's id
     * and when the code stops working, or why none was sent.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return \SineMacula\Laravel\Mfa\Codes\SendResult
     *
     * @throws \Throwable
     */
    #[\Override]
    public function send(Factor $factor, ProofBinding $binding): SendResult
    {
        $identity = $this->identity(PendingAction::SEND_CODE, $binding);

        if ($identity === null) {
            return SendResult::refused(FailureReason::NOT_FOUND);
        }

        $driver = $this->driver($factor);

        return $this->connection()->transaction(function () use ($identity, $factor, $binding, $driver): SendResult {

            $admission = $this->counters->isUsable($identity, $factor, $binding);

            return $admission->isAdmitted() ? $this->codes->send($factor, $binding, $driver) : SendResult::refusedBy($admission);
        });
    }

    /**
     * Whether the code answers the challenge, consuming it when it does, with
     * the outcome counted against the factor and the identity. A challenge that
     * may not go ahead is refused without checking the code, counting nothing.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  string  $challengeId
     * @param  string  $code
     * @return \SineMacula\Laravel\Mfa\Attempts\ChallengeOutcome
     *
     * @throws \Throwable
     */
    #[\Override]
    public function verify(Factor $factor, ProofBinding $binding, string $challengeId, #[\SensitiveParameter] string $code): ChallengeOutcome
    {
        $identity = $this->identity(PendingAction::VERIFY, $binding);

        if ($identity === null) {
            return ChallengeOutcome::refused(FailureReason::NOT_FOUND, 'The binding does not name the identity the request serves.');
        }

        return $this->connection()->transaction(function () use ($identity, $factor, $binding, $challengeId, $code): ChallengeOutcome {

            $admission = $this->counters->isUsable($identity, $factor, $binding);

            if (!$admission->isAdmitted()) {
                return ChallengeOutcome::refused($admission->reason ?? FailureReason::LOCKED, $admission->detail, $admission->lockedUntil);
            }

            $check   = $this->codes->check($factor, $binding, $code, $challengeId);
            $failure = $check->failure();
            $outcome = $this->counters->report($identity, $factor, $binding, $failure === null);

            return $failure === null && $outcome->passed
                ? ChallengeOutcome::passed()
                : ChallengeOutcome::failed($failure ?? FailureReason::INVALID_CODE, $check->detail());
        });
    }

    /**
     * The identity the request serves for the action, when the binding is the
     * caller's own: the same identity, application, session and purpose.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\PendingAction  $action
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return ?\SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    private function identity(PendingAction $action, ProofBinding $binding): ?MultiFactorAuthenticatable
    {
        $caller = $this->callers->resolve($action);

        if ($caller === null) {
            return null;
        }

        return $this->callers->binding($caller, $binding->purpose)?->toArray() === $binding->toArray() ? $caller->identity : null;
    }

    /**
     * The driver of the factor's type, which must deliver codes.
     *
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
     * The driver, which must deliver codes.
     *
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

    /**
     * The storage connection, where the counts and the codes live.
     *
     * @return \Illuminate\Database\ConnectionInterface
     *
     * @throws \InvalidArgumentException
     */
    private function connection(): ConnectionInterface
    {
        return DB::connection(StorageConnection::name());
    }
}
