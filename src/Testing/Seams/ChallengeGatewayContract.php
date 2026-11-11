<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams;

use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Contracts\ChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;

/**
 * What every `ChallengeGateway` must guarantee: a wrong code fails and is
 * counted, a code answers only its own binding and only once, and an unknown
 * challenge is not found. `$delivered` reads a sent code back, as from a fake
 * sender.
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
     * @param  \SineMacula\Laravel\Mfa\Contracts\ChallengeGateway  $gateway
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  \Closure(string): string  $delivered
     * @return void
     */
    public static function assertAWrongCodeIsRefused(ChallengeGateway $gateway, CallerContext $caller, Factor $factor, ProofBinding $binding, \Closure $delivered): void
    {
        $challenge = self::sent($gateway, $caller, $factor, $binding);
        $outcome   = $gateway->verify($caller, $factor, $binding, $challenge, self::wrong($delivered($challenge)));

        Assert::assertSame(FailureReason::INVALID_CODE, $outcome->reason, 'A code other than the one sent must fail as an invalid code.');
        Assert::assertTrue($outcome->counted, 'A code that was checked must be counted.');
    }

    /**
     * Another purpose's challenge is not found.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\ChallengeGateway  $gateway
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  \Closure(string): string  $delivered
     * @return void
     */
    public static function assertACodeAnswersOnlyItsOwnBinding(ChallengeGateway $gateway, CallerContext $caller, Factor $factor, ProofBinding $binding, \Closure $delivered): void
    {
        $challenge = self::sent($gateway, $caller, $factor, $binding);
        $code      = $delivered($challenge);
        $purpose   = $binding->purpose === Purpose::STEP_UP ? Purpose::SIGN_IN : Purpose::STEP_UP;
        $other     = new ProofBinding($binding->identityType, $binding->identityKey, $binding->application, $binding->sessionId, $purpose);

        Assert::assertFalse($gateway->verify($caller, $factor, $other, $challenge, $code)->hasPassed(), 'A code must not answer another purpose than the one it was sent for.');
        Assert::assertTrue($gateway->verify($caller, $factor, $binding, $challenge, $code)->hasPassed(), 'The code sent must answer its own binding.');
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\ChallengeGateway  $gateway
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  \Closure(string): string  $delivered
     * @return void
     */
    public static function assertACodeIsConsumedOnce(ChallengeGateway $gateway, CallerContext $caller, Factor $factor, ProofBinding $binding, \Closure $delivered): void
    {
        $challenge = self::sent($gateway, $caller, $factor, $binding);
        $code      = $delivered($challenge);

        Assert::assertTrue($gateway->verify($caller, $factor, $binding, $challenge, $code)->hasPassed(), 'The code sent must answer its challenge.');
        Assert::assertSame(FailureReason::REPLAYED, $gateway->verify($caller, $factor, $binding, $challenge, $code)->reason, 'A code must not answer its challenge twice.');
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\ChallengeGateway  $gateway
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return void
     */
    public static function assertAnUnknownChallengeIsNotFound(ChallengeGateway $gateway, CallerContext $caller, Factor $factor, ProofBinding $binding): void
    {
        $outcome = $gateway->verify($caller, $factor, $binding, 'unknown-challenge', '000000');

        Assert::assertSame(FailureReason::NOT_FOUND, $outcome->reason, 'A challenge that is not the binding\'s must not be found.');
    }

    /**
     * Fails the check unless the code is sent.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\ChallengeGateway  $gateway
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return string
     */
    private static function sent(ChallengeGateway $gateway, CallerContext $caller, Factor $factor, ProofBinding $binding): string
    {
        $challenge = $gateway->send($caller, $factor, $binding)->challengeId;

        Assert::assertNotNull($challenge, 'A code must be sent for a factor that may be challenged.');

        return $challenge;
    }

    /**
     * Same length, different code.
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
