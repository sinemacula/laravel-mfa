<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Drivers;

use SineMacula\Laravel\Mfa\Codes\CodeMessage;
use SineMacula\Laravel\Mfa\Contracts\CodeDeliveryDriver;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Enums\CodeCheck;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Secrets\RevealedSecret;

/**
 * Base for drivers whose codes are delivered to a destination. The challenge
 * gateway checks their codes, so `verify()` and `confirm()` refuse here.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
abstract class AbstractCodeDriver implements CodeDeliveryDriver
{
    /**
     * @return list<string>
     */
    #[\Override]
    public function amr(): array
    {
        return ['otp'];
    }

    /**
     * Each code is drawn when sent, so there is no secret to return.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @return null
     */
    #[\Override]
    public function startEnrollment(Factor $factor): ?RevealedSecret
    {
        return null;
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  string  $code
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return \SineMacula\Laravel\Mfa\Enums\CodeCheck
     *
     * @throws \LogicException
     */
    #[\Override]
    public function confirm(Factor $factor, #[\SensitiveParameter] string $code, ProofBinding $binding): CodeCheck
    {
        throw self::unbound('confirmed');
    }

    /**
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
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Codes\CodeMessage  $message
     * @return void
     */
    #[\Override]
    public function deliver(Factor $factor, #[\SensitiveParameter] CodeMessage $message): void
    {
        $this->send($message);
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Codes\CodeMessage  $message
     * @return void
     */
    abstract protected function send(#[\SensitiveParameter] CodeMessage $message): void;

    /**
     * @param  string  $action
     * @return \LogicException
     */
    private static function unbound(string $action): \LogicException
    {
        $message = 'A delivered code is bound to its factor, session, application and purpose, so it is %s through the code service, never by the driver alone.';

        return new \LogicException(sprintf($message, $action));
    }
}
