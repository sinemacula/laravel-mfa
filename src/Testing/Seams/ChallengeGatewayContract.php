<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams;

use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Mfa\Contracts\ChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;

/**
 * What every `ChallengeGateway` must guarantee, as assertions: a wrong code
 * fails and is counted, a code answers only the binding it was sent for, a code
 * is consumed once, and an unknown challenge is not found.
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
     * A code other than the one sent fails, and that was counted.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\ChallengeGateway  $gateway
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  \Closure(string): string  $delivered
     * @return void
     */
    public static function assertAWrongCodeIsRefused(ChallengeGateway $gateway, Factor $factor, ProofBinding $binding, \Closure $delivered): void
    {
        $challenge = self::sent($gateway, $factor, $binding);
        $outcome   = $gateway->verify($factor, $binding, $challenge, self::wrong($delivered($challenge)));

        Assert::assertSame(FailureReason::INVALID_CODE, $outcome->reason, 'A code other than the one sent must fail as an invalid code.');
        Assert::assertTrue($outcome->counted, 'A code that was checked must be counted.');
    }

    /**
     * The code sent answers its own binding, and no other purpose's, whose
     * challenge is not found.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\ChallengeGateway  $gateway
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  \Closure(string): string  $delivered
     * @return void
     */
    public static function assertACodeAnswersOnlyItsOwnBinding(ChallengeGateway $gateway, Factor $factor, ProofBinding $binding, \Closure $delivered): void
    {
        $challenge = self::sent($gateway, $factor, $binding);
        $code      = $delivered($challenge);
        $purpose   = $binding->purpose === Purpose::STEP_UP ? Purpose::SIGN_IN : Purpose::STEP_UP;
        $other     = new ProofBinding($binding->identityType, $binding->identityKey, $binding->application, $binding->sessionId, $purpose);

        Assert::assertFalse($gateway->verify($factor, $other, $challenge, $code)->hasPassed(), 'A code must not answer another purpose than the one it was sent for.');
        Assert::assertTrue($gateway->verify($factor, $binding, $challenge, $code)->hasPassed(), 'The code sent must answer its own binding.');
    }

    /**
     * The code sent answers once; used again, it is replayed.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\ChallengeGateway  $gateway
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  \Closure(string): string  $delivered
     * @return void
     */
    public static function assertACodeIsConsumedOnce(ChallengeGateway $gateway, Factor $factor, ProofBinding $binding, \Closure $delivered): void
    {
        $challenge = self::sent($gateway, $factor, $binding);
        $code      = $delivered($challenge);

        Assert::assertTrue($gateway->verify($factor, $binding, $challenge, $code)->hasPassed(), 'The code sent must answer its challenge.');
        Assert::assertSame(FailureReason::REPLAYED, $gateway->verify($factor, $binding, $challenge, $code)->reason, 'A code must not answer its challenge twice.');
    }

    /**
     * A challenge that is not the binding's is not found, whatever the code.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\ChallengeGateway  $gateway
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return void
     */
    public static function assertAnUnknownChallengeIsNotFound(ChallengeGateway $gateway, Factor $factor, ProofBinding $binding): void
    {
        $outcome = $gateway->verify($factor, $binding, 'unknown-challenge', '000000');

        Assert::assertSame(FailureReason::NOT_FOUND, $outcome->reason, 'A challenge that is not the binding\'s must not be found.');
    }

    /**
     * Send a code, which must be sent, and return its challenge's id.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\ChallengeGateway  $gateway
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return string
     */
    private static function sent(ChallengeGateway $gateway, Factor $factor, ProofBinding $binding): string
    {
        $challenge = $gateway->send($factor, $binding)->challengeId;

        Assert::assertNotNull($challenge, 'A code must be sent for a factor that may be challenged.');

        return $challenge;
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
