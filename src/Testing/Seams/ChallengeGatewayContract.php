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
 * counted, a code answers only its own binding and only once, another caller's
 * binding and an unknown challenge are not found, and a challenge takes no more
 * than its wrong codes. `$delivered` reads a sent code back, as from a fake
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
     * Another purpose, session or application than the one the code was sent
     * for.
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

        foreach (['purpose' => 'purpose', 'session_id' => 'session', 'application' => 'application'] as $part => $name) {
            $message = sprintf('A code must not answer another %s than the one it was sent for.', $name);

            Assert::assertFalse($gateway->verify($caller, $factor, self::another($binding, $part), $challenge, $code)->hasPassed(), $message);
        }

        Assert::assertTrue($gateway->verify($caller, $factor, $binding, $challenge, $code)->hasPassed(), 'The code sent must answer its own binding.');
    }

    /**
     * Another identity's binding, or the binding asked by a caller who is
     * nobody, is refused uncounted and leaves the code to answer its own.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\ChallengeGateway  $gateway
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  \Closure(string): string  $delivered
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public static function assertAnotherCallersBindingIsNotFound(ChallengeGateway $gateway, CallerContext $caller, Factor $factor, ProofBinding $binding, \Closure $delivered): void
    {
        $challenge = self::sent($gateway, $caller, $factor, $binding);
        $code      = $delivered($challenge);

        $asked = [
            [$caller, self::another($binding, 'identity_key')],
            [$caller, self::another($binding, 'identity_type')],
            [CallerContext::nobody($caller->application, $caller->client), $binding],
        ];

        foreach ($asked as [$asking, $named]) {
            $outcome = $gateway->verify($asking, $factor, $named, $challenge, $code);

            Assert::assertSame(FailureReason::NOT_FOUND, $outcome->reason, 'A binding that does not name the caller must not be found.');
            Assert::assertFalse($outcome->counted, 'A binding that does not name the caller must not be counted.');
        }

        Assert::assertTrue($gateway->verify($caller, $factor, $binding, $challenge, $code)->hasPassed(), 'A binding that does not name the caller must not use up the code.');
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\ChallengeGateway  $gateway
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  \Closure(string): string  $delivered
     * @param  int  $maxAttempts
     * @return void
     */
    public static function assertAChallengeTakesNoMoreThanItsAttempts(
        ChallengeGateway $gateway,
        CallerContext $caller,
        Factor $factor,
        ProofBinding $binding,
        \Closure $delivered,
        int $maxAttempts,
    ): void {
        $challenge = self::sent($gateway, $caller, $factor, $binding);
        $code      = $delivered($challenge);
        $wrong     = self::wrong($code);

        for ($attempt = 0; $attempt < $maxAttempts; $attempt++) {
            Assert::assertFalse($gateway->verify($caller, $factor, $binding, $challenge, $wrong)->hasPassed(), 'A code other than the one sent must not pass.');
        }

        Assert::assertFalse($gateway->verify($caller, $factor, $binding, $challenge, $code)->hasPassed(), 'The code sent must not pass once its challenge has taken its attempts.');
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
     * The binding with one part, by its serialised name, naming another.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  string  $part
     * @return \SineMacula\Laravel\Mfa\Proofs\ProofBinding
     */
    private static function another(ProofBinding $binding, string $part): ProofBinding
    {
        $fields  = $binding->toArray();
        $purpose = $binding->purpose === Purpose::STEP_UP ? Purpose::SIGN_IN : Purpose::STEP_UP;

        $fields[$part] = $part === 'purpose' ? $purpose->value : $fields[$part] . '-other';

        return ProofBinding::fromArray($fields);
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
