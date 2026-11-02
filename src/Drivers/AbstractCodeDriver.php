<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Drivers;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Contracts\CodeDeliveryDriver;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Enums\CodeCheck;
use SineMacula\Laravel\Mfa\Exceptions\MissingDestinationException;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;

/**
 * Base class for the drivers whose codes are delivered to a destination (email,
 * SMS).
 *
 * The bound `ChallengeGateway` draws, stores and checks their codes, bound to
 * the factor, the identity, the application, the session and the purpose (see
 * `Codes\CodeService`), so a concrete driver only describes its channel and its
 * transport: how a code reaches the factor's destination. A factor with no
 * destination is refused before anything is sent.
 *
 * The driver holds no code to compare, so `verify()` and `confirm()` refuse
 * with a `LogicException` rather than accept a code checked by nothing. Such a
 * type keeps no secret, so starting an enrolment returns none.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
abstract class AbstractCodeDriver implements CodeDeliveryDriver
{
    /**
     * The `amr` value of a code sent to the factor: `otp`.
     *
     * @return list<string>
     */
    #[\Override]
    public function amr(): array
    {
        return ['otp'];
    }

    /**
     * Delivered codes keep no persistent secret: each is drawn when it is sent,
     * so starting an enrolment returns none.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @return null
     */
    #[\Override]
    public function startEnrollment(Factor $factor): ?string
    {
        return null;
    }

    /**
     * Refuse: a pending factor is confirmed with a code checked under its
     * binding, through the code service.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  string  $code
     * @return bool
     *
     * @throws \LogicException
     *
     * @imperative
     */
    #[\Override]
    public function confirm(Factor $factor, #[\SensitiveParameter] string $code): bool
    {
        throw self::unbound('confirmed');
    }

    /**
     * Refuse: a code is checked under its binding, through the challenge
     * gateway.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  string  $code
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return \SineMacula\Laravel\Mfa\Enums\CodeCheck
     *
     * @throws \LogicException
     */
    #[\Override]
    public function verify(Factor $factor, #[\SensitiveParameter] string $code, ProofBinding $binding): CodeCheck
    {
        throw self::unbound('checked');
    }

    /**
     * Deliver the code to the factor's destination through the driver's
     * transport.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  string  $code
     * @param  \Carbon\CarbonImmutable  $expiresAt
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\MissingDestinationException
     */
    #[\Override]
    public function deliver(Factor $factor, #[\SensitiveParameter] string $code, CarbonImmutable $expiresAt): void
    {
        $destination = $factor->getDestination();

        if ($destination === null || $destination === '') {
            throw new MissingDestinationException(sprintf('The %s factor has no destination, so its code cannot be delivered.', $factor->getType()));
        }

        $this->send($destination, $code, $expiresAt);
    }

    /**
     * Send the code to the destination through the driver's transport.
     *
     * @param  string  $destination
     * @param  string  $code
     * @param  \Carbon\CarbonImmutable  $expiresAt
     * @return void
     */
    abstract protected function send(#[\SensitiveParameter] string $destination, #[\SensitiveParameter] string $code, CarbonImmutable $expiresAt): void;

    /**
     * The refusal of a factor-only call for a code that needs its binding.
     *
     * @param  string  $action
     * @return \LogicException
     */
    private static function unbound(string $action): \LogicException
    {
        $message = 'A delivered code is bound to its factor, session, application and purpose, so it is %s through the code service, never by the driver alone.';

        return new \LogicException(sprintf($message, $action));
    }
}
