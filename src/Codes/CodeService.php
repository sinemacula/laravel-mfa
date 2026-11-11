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
 * Sends and checks delivered codes. Sends run under the identity's factor lock
 * so parallel requests cannot overrun the caps, and delivery happens inside the
 * same transaction so a failed delivery keeps no code and spends no cap.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CodeService
{
    /**
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** Resolves the code engine. */
        private Container $container,
    ) {}

    /**
     * Start a challenge or resend the binding's open one.
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

        if (!ProofOwner::of($identity)->owns($binding)) {
            throw new \InvalidArgumentException('A code is sent to the identity its binding names.');
        }

        $codes = $this->container->make(DeliveredCodes::class);

        return FactorStateTransaction::forFactor($stored, static function (Collection $factors) use ($identity, $stored, $binding, $driver, $codes): SendResult {

            // Read under the lock so a send that waited is timed when it ran
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
     * Consume the challenge's code when it matches.
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
     * A failure is scrubbed of the code and destination and rethrown, so the
     * transaction still rolls back.
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

            // Without a summary there is nothing to name the factor by
            throw $summary === null ? $exception : new CodeDeliveryFailedException($summary, $exception);
        }
    }

    /**
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
