<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Codes;

use Illuminate\Contracts\Container\Container;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Mfa\Attempts\ChallengeCounters;
use SineMacula\Laravel\Mfa\Context\CallerContextResolver;
use SineMacula\Laravel\Mfa\Contracts\ChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\CodeDeliveryDriver;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Database\StorageConnection;
use SineMacula\Laravel\Mfa\Drivers\DriverResolver;
use SineMacula\Laravel\Mfa\Enums\CodeCheck;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Exceptions\UnsupportedFactorException;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;

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
 * pending session allows sending or verifying, or its signed-in person is the
 * identity the binding names.
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
     * Send a code for the factor, bound as the binding says, and return the
     * challenge's id. A challenge that may not go ahead, or a code that is not
     * sent, is refused with an `OperationRefusedException` carrying why.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return string
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     * @throws \Throwable
     */
    #[\Override]
    public function send(Factor $factor, ProofBinding $binding): string
    {
        $identity = $this->identity(PendingAction::SEND_CODE, $binding)
            ?? throw new OperationRefusedException(FailureReason::NOT_FOUND, 'The binding does not name the identity the request serves.');

        $driver = $this->driver($factor);

        return $this->connection()->transaction(function () use ($identity, $factor, $binding, $driver): string {

            $admission = $this->counters->isUsable($identity, $factor, $binding);

            if (!$admission->isAdmitted()) {
                throw new OperationRefusedException($admission->reason ?? FailureReason::LOCKED, $admission->detail);
            }

            $result = $this->codes->send($identity, $factor, $binding, $driver);

            return $result->challengeId ?? throw new OperationRefusedException($result->reason ?? FailureReason::SENDING_CAPPED, 'No code was sent.');
        });
    }

    /**
     * Whether the code answers the challenge, consuming it when it does, with
     * the outcome counted against the factor and the identity. A challenge
     * that may not go ahead is answered `false` without checking the code.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  string  $challengeId
     * @param  string  $code
     * @return bool
     *
     * @throws \Throwable
     */
    #[\Override]
    public function verify(Factor $factor, ProofBinding $binding, string $challengeId, #[\SensitiveParameter] string $code): bool
    {
        $identity = $this->identity(PendingAction::VERIFY, $binding);

        if ($identity === null) {
            return false;
        }

        return $this->connection()->transaction(function () use ($identity, $factor, $binding, $challengeId, $code): bool {

            if (!$this->counters->isUsable($identity, $factor, $binding)->isAdmitted()) {
                return false;
            }

            $passed = $this->codes->check($factor, $binding, $code, $challengeId) === CodeCheck::ACCEPTED;

            return $this->counters->report($identity, $factor, $binding, $passed)->passed;
        });
    }

    /**
     * The identity the request serves for the action, when the binding names
     * it.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\PendingAction  $action
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return ?\SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    private function identity(PendingAction $action, ProofBinding $binding): ?MultiFactorAuthenticatable
    {
        $caller = $this->callers->resolve($action);

        return $caller !== null && ProofOwner::of($caller->identity)->owns($binding) ? $caller->identity : null;
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
        $driver = $this->container->make(DriverResolver::class)->fromContainer($this->container, $factor->getType());

        if (!$driver instanceof CodeDeliveryDriver) {
            throw new UnsupportedFactorException(sprintf('The factor\'s type [%s] does not deliver codes.', $factor->getType()));
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
