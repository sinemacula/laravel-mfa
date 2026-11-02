<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Verification;

use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Assurance\ObservedProperties;
use SineMacula\Laravel\Mfa\Attempts\Attempt;
use SineMacula\Laravel\Mfa\Attempts\AttemptOutcome;
use SineMacula\Laravel\Mfa\Attempts\AttemptService;
use SineMacula\Laravel\Mfa\Contracts\ChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\CodeDeliveryDriver;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\FactorDriver;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Enums\CodeCheck;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\SubmissionKind;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyAssertion;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyAssertions;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService;

/**
 * Checks a submission along its one route and counts it exactly once, under the
 * identity's factor state lock, which the caller holds.
 *
 * A code for a factor that makes its own goes to the factor's driver and a
 * passkey's response to the bound gateway, each as an attempt through
 * `Attempts\AttemptService`; a recovery code is redeemed, which is such an
 * attempt too. A code answering a challenge goes to the bound
 * `ChallengeGateway`, which reports its outcome through
 * `Attempts\ChallengeCounters` itself, so it is not counted again here.
 *
 * What a route writes (a TOTP step, a code's use, the count) stays in the
 * transaction, so a refusal that follows rolls it back.
 *
 * Stateless: the seams are resolved on every call.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SubmissionRoutes
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\Mfa\Attempts\AttemptService  $attempts
     * @param  \SineMacula\Laravel\Mfa\Passkeys\PasskeyAssertions  $passkeys
     * @param  \SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService  $recoveryCodes
     */
    public function __construct(

        /** The container the challenge gateway is resolved from. */
        private Container $container,

        /** The counts a route is made through. */
        private AttemptService $attempts,

        /** The ceremony checks of a passkey. */
        private PasskeyAssertions $passkeys,

        /** The recovery code set. */
        private RecoveryCodeService $recoveryCodes,
    ) {}

    /**
     * Whether the submission is the kind the factor's route takes: a delivered
     * factor must name a challenge, a passkey takes an assertion, and any other
     * factor takes a code.
     *
     * @param  \SineMacula\Laravel\Mfa\Verification\Submission  $submission
     * @param  \SineMacula\Laravel\Mfa\Contracts\FactorDriver  $driver
     * @param  string  $type
     * @return bool
     */
    public static function fits(Submission $submission, FactorDriver $driver, string $type): bool
    {
        if ($driver instanceof CodeDeliveryDriver) {
            return $submission->kind === SubmissionKind::CHALLENGE;
        }

        return $submission->kind === ($type === PasskeyAssertions::TYPE ? SubmissionKind::ASSERTION : SubmissionKind::FACTOR);
    }

    /**
     * Redeem the submitted recovery code.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Verification\Submission  $submission
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return \SineMacula\Laravel\Mfa\Verification\CheckOutcome
     *
     * @throws \Throwable
     */
    public function recoveryCode(MultiFactorAuthenticatable $identity, #[\SensitiveParameter] Submission $submission, ProofBinding $binding): CheckOutcome
    {
        $redemption = $this->recoveryCodes->redeem($identity, $submission->code ?? '', $binding);
        $reason     = $redemption->reason;

        return match (true) {
            $reason === null     => CheckOutcome::passed(ObservedProperties::none(), remaining: $redemption->remaining ?? 0),
            $redemption->counted => CheckOutcome::failed($reason, $redemption->detail ?? 'The code matched no unused recovery code.'),
            default              => CheckOutcome::refused($reason, $redemption->detail ?? 'The redemption was refused.', $redemption->lockedUntil),
        };
    }

    /**
     * Check the submission against the factor as stored under the lock, along
     * the route its kind takes.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Verification\Submission  $submission
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  \SineMacula\Laravel\Mfa\Contracts\FactorDriver  $driver
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return \SineMacula\Laravel\Mfa\Verification\CheckOutcome
     *
     * @throws \Throwable
     */
    public function factor(
        MultiFactorAuthenticatable $identity,
        #[\SensitiveParameter] Submission $submission,
        EloquentFactor&Model $factor,
        FactorDriver $driver,
        ProofBinding $binding,
    ): CheckOutcome {
        return match ($submission->kind) {
            SubmissionKind::CHALLENGE => $this->challenge($submission, $factor, $binding),
            SubmissionKind::ASSERTION => $this->assertion($identity, $submission, $factor, $binding),
            default                   => $this->code($identity, $submission, $factor, $driver, $binding),
        };
    }

    /**
     * Check the code through the factor's driver, as an attempt.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Verification\Submission  $submission
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  \SineMacula\Laravel\Mfa\Contracts\FactorDriver  $driver
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return \SineMacula\Laravel\Mfa\Verification\CheckOutcome
     *
     * @throws \Throwable
     */
    private function code(
        MultiFactorAuthenticatable $identity,
        #[\SensitiveParameter] Submission $submission,
        EloquentFactor&Model $factor,
        FactorDriver $driver,
        ProofBinding $binding,
    ): CheckOutcome {
        $check = CodeCheck::INVALID;

        $outcome = $this->attempts->attempt(
            new Attempt($identity, $factor, $binding->purpose, $binding->application),
            static function () use ($driver, $factor, $submission, $binding, &$check): bool {

                $check = $driver->verify($factor, $submission->code ?? '', $binding);

                return $check === CodeCheck::ACCEPTED;
            },
        );

        return self::fromAttempt($outcome)
            ?? ($outcome->passed ? CheckOutcome::passed(ObservedProperties::none()) : CheckOutcome::failed($check->failure() ?? FailureReason::INVALID_CODE, $check->detail()));
    }

    /**
     * Check the passkey's response through the gateway, as an attempt.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Verification\Submission  $submission
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return \SineMacula\Laravel\Mfa\Verification\CheckOutcome
     *
     * @throws \Throwable
     */
    private function assertion(
        MultiFactorAuthenticatable $identity,
        #[\SensitiveParameter] Submission $submission,
        EloquentFactor&Model $factor,
        ProofBinding $binding,
    ): CheckOutcome {
        $assertion = FailureReason::INVALID_CODE;

        $outcome = $this->attempts->attempt(
            new Attempt($identity, $factor, $binding->purpose, $binding->application),
            function () use ($identity, $factor, $binding, $submission, &$assertion): bool {

                $assertion = $this->passkeys->check($identity, $factor, $binding, $submission->response);

                return $assertion instanceof PasskeyAssertion;
            },
        );

        return self::fromAttempt($outcome)
            ?? ($assertion instanceof PasskeyAssertion
                ? CheckOutcome::passed($assertion->properties, $assertion->challengeId)
                : CheckOutcome::failed($assertion, 'The passkey assertion did not verify.'));
    }

    /**
     * Check the code through the bound gateway, which owns the challenge and
     * reports its outcome.
     *
     * @param  \SineMacula\Laravel\Mfa\Verification\Submission  $submission
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return \SineMacula\Laravel\Mfa\Verification\CheckOutcome
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function challenge(#[\SensitiveParameter] Submission $submission, EloquentFactor&Model $factor, ProofBinding $binding): CheckOutcome
    {
        $challengeId = $submission->challengeId ?? '';
        $outcome     = $this->container->make(ChallengeGateway::class)->verify($factor, $binding, $challengeId, $submission->code ?? '');
        $reason      = $outcome->reason;

        return match (true) {
            $reason === null  => CheckOutcome::passed(ObservedProperties::none(), $challengeId),
            $outcome->counted => CheckOutcome::failed($reason, $outcome->detail),
            default           => CheckOutcome::refused($reason, $outcome->detail, $outcome->lockedUntil),
        };
    }

    /**
     * The refusal an attempt that never reached its check ended in: a lockout,
     * or a factor no longer stored.
     *
     * @param  \SineMacula\Laravel\Mfa\Attempts\AttemptOutcome  $outcome
     * @return ?\SineMacula\Laravel\Mfa\Verification\CheckOutcome
     */
    private static function fromAttempt(AttemptOutcome $outcome): ?CheckOutcome
    {
        return match (true) {
            $outcome->lockout !== null => CheckOutcome::refused(FailureReason::LOCKED, $outcome->lockout->detail(), $outcome->lockout->until),
            $outcome->isNotFound()     => CheckOutcome::refused(FailureReason::NOT_FOUND, 'The factor is no longer among the identity\'s factors.'),
            default                    => null,
        };
    }
}
