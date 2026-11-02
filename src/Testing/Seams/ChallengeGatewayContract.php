<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams;

use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Mfa\Contracts\ChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;

/**
 * What every `ChallengeGateway` must guarantee, as assertions: a wrong code is
 * refused, a code answers only the binding it was sent for, and a code is
 * consumed once.
 *
 * Each assertion sends one code for the factor and reads it back through the
 * closure given, as a test reads it from a fake sender.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final class ChallengeGatewayContract
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * A code other than the one sent is refused.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\ChallengeGateway  $gateway
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  \Closure(string): string  $delivered
     * @return void
     */
    public static function assertAWrongCodeIsRefused(ChallengeGateway $gateway, Factor $factor, ProofBinding $binding, \Closure $delivered): void
    {
        $challenge = $gateway->send($factor, $binding);

        Assert::assertFalse($gateway->verify($factor, $binding, $challenge, self::wrong($delivered($challenge))), 'A code other than the one sent must be refused.');
    }

    /**
     * The code sent answers its own binding, and no other purpose's.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\ChallengeGateway  $gateway
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  \Closure(string): string  $delivered
     * @return void
     */
    public static function assertACodeAnswersOnlyItsOwnBinding(ChallengeGateway $gateway, Factor $factor, ProofBinding $binding, \Closure $delivered): void
    {
        $challenge = $gateway->send($factor, $binding);
        $code      = $delivered($challenge);
        $purpose   = $binding->purpose === Purpose::STEP_UP ? Purpose::SIGN_IN : Purpose::STEP_UP;
        $other     = new ProofBinding($binding->identityType, $binding->identityKey, $binding->application, $binding->sessionId, $purpose);

        Assert::assertFalse($gateway->verify($factor, $other, $challenge, $code), 'A code must not answer another purpose than the one it was sent for.');
        Assert::assertTrue($gateway->verify($factor, $binding, $challenge, $code), 'The code sent must answer its own binding.');
    }

    /**
     * The code sent answers once.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\ChallengeGateway  $gateway
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  \Closure(string): string  $delivered
     * @return void
     */
    public static function assertACodeIsConsumedOnce(ChallengeGateway $gateway, Factor $factor, ProofBinding $binding, \Closure $delivered): void
    {
        $challenge = $gateway->send($factor, $binding);
        $code      = $delivered($challenge);

        Assert::assertTrue($gateway->verify($factor, $binding, $challenge, $code), 'The code sent must answer its challenge.');
        Assert::assertFalse($gateway->verify($factor, $binding, $challenge, $code), 'A code must not answer its challenge twice.');
    }

    /**
     * A code of the same length that is not the one given.
     *
     * @param  string  $code
     * @return string
     */
    private static function wrong(#[\SensitiveParameter] string $code): string
    {
        $zeros = str_repeat('0', strlen($code));

        return $code === $zeros ? str_repeat('1', strlen($code)) : $zeros;
    }
}
