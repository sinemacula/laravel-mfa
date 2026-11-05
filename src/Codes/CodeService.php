<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Codes;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Contracts\CodeDeliveryDriver;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Enums\CodeCheck;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Exceptions\CodeDeliveryFailedException;
use SineMacula\Laravel\Mfa\Exceptions\MissingDestinationException;
use SineMacula\Laravel\Mfa\Exceptions\UnsupportedFactorException;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Secrets\ExceptionScrubber;
use SineMacula\Laravel\Mfa\Secrets\RevealedSecret;
use SineMacula\Laravel\Mfa\Support\FactorOwnerColumns;
use SineMacula\Laravel\Mfa\Support\FactorStateTransaction;

/**
 * Sends a delivered factor's codes and checks the codes submitted for it, each
 * bound to the factor and to a binding: the identity, the application, the
 * session and the purpose (see `DeliveredCodes`).
 *
 * Sending runs in the identity's factor state transaction (see
 * `FactorStateTransaction`), so the sends of one identity are serialised and
 * the caps on them cannot be overrun by parallel requests; the factor is read
 * again under the lock, and one a concurrent change removed is `not_found`. The
 * time of a send is read once the locks are held, never before. The code is
 * stored, then delivered by the factor's driver inside the same transaction, so
 * a delivery that throws keeps no code and spends no cooldown or cap. The
 * driver is handed a `CodeMessage`: the application and the purpose from the
 * binding, the factor's type and destination as locked, the code and its
 * expiry, and the identity the code is for. Neither sending nor checking resets
 * a failure count or lifts a lockout, and neither reports anything: `CodeSent`
 * and the verification events are dispatched by
 * `Verification\VerificationService`, whichever gateway the code went through.
 *
 * A delivery that throws is scrubbed of the code and the factor's destination,
 * which the service knows, in the message and the trace of every exception in
 * its chain, whether or not PHP recorded the arguments, and surfaces as a
 * `CodeDeliveryFailedException` naming the destination only masked, with the
 * scrubbed failure as its previous exception.
 *
 * A delivered code needs a stored factor and a binding naming the factor's
 * owner, which is the identity the code is for: anything else is refused before
 * anything is read.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CodeService
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The container the engine is resolved from. */
        private Container $container,
    ) {}

    /**
     * Send a code for the factor under the binding to the identity through the
     * factor's driver: a new challenge, or a resend of the binding's open one.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  \SineMacula\Laravel\Mfa\Contracts\CodeDeliveryDriver  $driver
     * @return \SineMacula\Laravel\Mfa\Codes\SendResult
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\CodeDeliveryFailedException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedFactorException
     * @throws \Throwable
     */
    public function send(MultiFactorAuthenticatable $identity, Factor $factor, ProofBinding $binding, CodeDeliveryDriver $driver): SendResult
    {
        $stored = self::stored($factor, $binding);

        self::refuseAnotherRecipient($identity, $binding);

        $codes = $this->container->make(DeliveredCodes::class);

        return FactorStateTransaction::forFactor($stored, static function (Collection $factors) use ($identity, $stored, $binding, $driver, $codes): SendResult {

            // Read once the locks are held, so a send that waited for them is
            // timed, and its cooldown and expiry run, from when it was made
            $now    = CarbonImmutable::now()->startOfSecond();
            $locked = $factors->first(static fn (Model $candidate): bool => $candidate->is($stored));

            if ($locked === null) {
                return SendResult::refused(FailureReason::NOT_FOUND);
            }

            $issued = $codes->issue(self::idOf($stored), $binding, $now, $locked->getDestination());

            if (is_int($issued)) {
                return SendResult::refused(FailureReason::SENDING_CAPPED, $issued);
            }

            self::deliver($driver, $locked, $issued, $binding, $identity);

            return SendResult::sent($issued->challengeId, $issued->expiresAt);
        });
    }

    /**
     * Check the code against the factor's challenge named under the binding,
     * using it up when it matches.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  string  $code
     * @param  string  $challengeId
     * @return \SineMacula\Laravel\Mfa\Enums\CodeCheck
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedFactorException
     */
    public function check(Factor $factor, ProofBinding $binding, #[\SensitiveParameter] string $code, string $challengeId): CodeCheck
    {
        $stored = self::stored($factor, $binding);

        return $this->container->make(DeliveredCodes::class)->check(self::idOf($stored), $binding, $code, CarbonImmutable::now()->startOfSecond(), $challengeId);
    }

    /**
     * Deliver the issued code to the identity through the factor's driver, in a
     * message built from the binding and the factor as locked. A factor with no
     * destination is refused there. A failure, building the message included,
     * is scrubbed of the code and the factor's destination, which are given to
     * the scrub rather than read from the trace, and rethrown as a
     * `CodeDeliveryFailedException`, so the transaction still rolls back; one
     * reading the factor before it could be summarised is rethrown scrubbed as
     * it is, since nothing could name the factor.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\CodeDeliveryDriver  $driver
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Codes\IssuedCode  $issued
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\CodeDeliveryFailedException
     * @throws \Throwable
     */
    private static function deliver(
        CodeDeliveryDriver $driver,
        Factor $factor,
        #[\SensitiveParameter] IssuedCode $issued,
        ProofBinding $binding,
        #[\SensitiveParameter] MultiFactorAuthenticatable $identity,
    ): void {
        $destination = null;
        $summary     = null;

        try {
            $destination = $factor->getDestination();
            $summary     = FactorSummary::fromFactor($factor);

            $driver->deliver($factor, new CodeMessage(
                application: $binding->application,
                purpose    : $binding->purpose,
                type       : $factor->getType(),
                destination: self::destinationOf($factor, $destination),
                code       : new RevealedSecret($issued->code),
                expiresAt  : $issued->expiresAt,
                recipient  : $identity,
                factor     : $summary,
            ));
        } catch (\Throwable $exception) {
            ExceptionScrubber::scrub($exception, $issued->code, $destination);

            // A factor that could not be summarised is not read again: its
            // failure goes on scrubbed, and still rolls the code back
            throw $summary === null ? $exception : new CodeDeliveryFailedException($summary, $exception);
        }
    }

    /**
     * Refuse to send a code to another identity than the one its binding names.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function refuseAnotherRecipient(MultiFactorAuthenticatable $identity, ProofBinding $binding): void
    {
        if (!ProofOwner::of($identity)->owns($binding)) {
            throw new \InvalidArgumentException('A code is sent to the identity its binding names.');
        }
    }

    /**
     * The factor's destination, refusing a factor that has none.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  ?string  $destination
     * @return string
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\MissingDestinationException
     */
    private static function destinationOf(Factor $factor, #[\SensitiveParameter] ?string $destination): string
    {
        if ($destination === null || $destination === '') {
            throw new MissingDestinationException(sprintf('The %s factor has no destination, so its code cannot be delivered.', $factor->getType()));
        }

        return $destination;
    }

    /**
     * The factor as a stored model owned by the binding's identity.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedFactorException
     */
    private static function stored(Factor $factor, ProofBinding $binding): EloquentFactor&Model
    {
        if (!$factor instanceof EloquentFactor || !$factor instanceof Model || !$factor->exists) {
            throw new UnsupportedFactorException('Delivered codes need a stored EloquentFactor model; got ' . get_debug_type($factor) . '.');
        }

        [$typeColumn, $keyColumn] = FactorOwnerColumns::of($factor);

        $key = $factor->getAttribute($keyColumn);

        if ($factor->getAttribute($typeColumn) !== $binding->identityType || (!is_string($key) && !is_int($key)) || (string) $key !== $binding->identityKey) {
            throw new \InvalidArgumentException('A delivered code\'s binding must name the identity that owns the factor.');
        }

        return $factor;
    }

    /**
     * The stored factor's id, as the codes table records it.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @return string
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedFactorException
     */
    private static function idOf(EloquentFactor&Model $factor): string
    {
        $id = $factor->getKey();

        if ((!is_string($id) && !is_int($id)) || $id === '') {
            throw new UnsupportedFactorException('A delivered code needs a factor with a string or integer key.');
        }

        return (string) $id;
    }
}
