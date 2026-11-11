<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Verification;

use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Assurance\ObservedProperties;
use SineMacula\Laravel\Mfa\Attempts\Attempt;
use SineMacula\Laravel\Mfa\Attempts\AttemptOutcome;
use SineMacula\Laravel\Mfa\Attempts\AttemptService;
use SineMacula\Laravel\Mfa\Context\Caller;
use SineMacula\Laravel\Mfa\Contracts\ChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\CodeDeliveryDriver;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\FactorDriver;
use SineMacula\Laravel\Mfa\Enums\CodeCheck;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\SubmissionKind;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyAssertion;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyAssertions;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService;

/**
 * Checks a submission along its one route and counts it exactly once, under the
 * identity's lock the caller holds; a challenge's gateway counts its own.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SubmissionRoutes
{
    /**
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\Mfa\Attempts\AttemptService  $attempts
     * @param  \SineMacula\Laravel\Mfa\Passkeys\PasskeyAssertions  $passkeys
     * @param  \SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService  $recoveryCodes
     */
    public function __construct(

        /** Resolves the challenge gateway on every call. */
        private Container $container,

        /** Counts each route's attempt. */
        private AttemptService $attempts,

        /** Passkey ceremony checks. */
        private PasskeyAssertions $passkeys,

        /** Redeems recovery codes. */
        private RecoveryCodeService $recoveryCodes,
    ) {}

    /**
     * A delivered factor takes a challenge, a passkey an assertion, and any
     * other factor a code.
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
     * @param  \SineMacula\Laravel\Mfa\Context\Caller  $caller
     * @param  \SineMacula\Laravel\Mfa\Verification\Submission  $submission
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return \SineMacula\Laravel\Mfa\Verification\CheckOutcome
     *
     * @throws \Throwable
     */
    public function recoveryCode(Caller $caller, #[\SensitiveParameter] Submission $submission, ProofBinding $binding): CheckOutcome
    {
        $redemption = $this->recoveryCodes->redeem($caller->identity, $submission->code() ?? '', $binding, $caller->client);
        $reason     = $redemption->reason;

        return match (true) {
            $reason === null     => CheckOutcome::passed(ObservedProperties::none(), remaining: $redemption->remaining ?? 0),
            $redemption->counted => CheckOutcome::failed($reason, $redemption->detail ?? 'The code matched no unused recovery code.'),
            default              => CheckOutcome::refused($reason, $redemption->detail ?? 'The redemption was refused.', $redemption->lockedUntil),
        };
    }

    /**
     * Check against the factor as stored under the lock.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\Caller  $caller
     * @param  \SineMacula\Laravel\Mfa\Verification\Submission  $submission
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  \SineMacula\Laravel\Mfa\Contracts\FactorDriver  $driver
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return \SineMacula\Laravel\Mfa\Verification\CheckOutcome
     *
     * @throws \Throwable
     */
    public function factor(Caller $caller, #[\SensitiveParameter] Submission $submission, EloquentFactor&Model $factor, FactorDriver $driver, ProofBinding $binding): CheckOutcome
    {
        return match ($submission->kind) {
            SubmissionKind::CHALLENGE => $this->challenge($caller, $submission, $factor, $binding),
            SubmissionKind::ASSERTION => $this->assertion($caller, $submission, $factor, $binding),
            default                   => $this->code($caller, $submission, $factor, $driver, $binding),
        };
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Context\Caller  $caller
     * @param  \SineMacula\Laravel\Mfa\Verification\Submission  $submission
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  \SineMacula\Laravel\Mfa\Contracts\FactorDriver  $driver
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return \SineMacula\Laravel\Mfa\Verification\CheckOutcome
     *
     * @throws \Throwable
     */
    private function code(Caller $caller, #[\SensitiveParameter] Submission $submission, EloquentFactor&Model $factor, FactorDriver $driver, ProofBinding $binding): CheckOutcome
    {
        $check = CodeCheck::INVALID;

        $outcome = $this->attempts->attempt(
            new Attempt($caller->identity, $factor, $binding->purpose, $binding->application, $caller->client),
            static function () use ($driver, $factor, $submission, $binding, &$check): bool {

                $check = $driver->verify($factor, $submission->code() ?? '', $binding);

                return $check === CodeCheck::ACCEPTED;
            },
        );

        return self::fromAttempt($outcome)
            ?? ($outcome->passed ? CheckOutcome::passed(ObservedProperties::none()) : CheckOutcome::failed($check->failure() ?? FailureReason::INVALID_CODE, $check->detail()));
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Context\Caller  $caller
     * @param  \SineMacula\Laravel\Mfa\Verification\Submission  $submission
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return \SineMacula\Laravel\Mfa\Verification\CheckOutcome
     *
     * @throws \Throwable
     */
    private function assertion(Caller $caller, #[\SensitiveParameter] Submission $submission, EloquentFactor&Model $factor, ProofBinding $binding): CheckOutcome
    {
        $assertion = FailureReason::INVALID_CODE;

        $outcome = $this->attempts->attempt(
            new Attempt($caller->identity, $factor, $binding->purpose, $binding->application, $caller->client),
            function () use ($caller, $factor, $binding, $submission, &$assertion): bool {

                $assertion = $this->passkeys->check($caller->identity, $factor, $binding, $submission->response(), $caller->pending);

                return $assertion instanceof PasskeyAssertion;
            },
        );

        return self::fromAttempt($outcome)
            ?? ($assertion instanceof PasskeyAssertion
                ? CheckOutcome::passed($assertion->properties, $assertion->challengeId)
                : CheckOutcome::failed($assertion, 'The passkey assertion did not verify.'));
    }

    /**
     * The gateway owns the challenge and reports its outcome.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\Caller  $caller
     * @param  \SineMacula\Laravel\Mfa\Verification\Submission  $submission
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return \SineMacula\Laravel\Mfa\Verification\CheckOutcome
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function challenge(Caller $caller, #[\SensitiveParameter] Submission $submission, EloquentFactor&Model $factor, ProofBinding $binding): CheckOutcome
    {
        $challengeId = $submission->challengeId ?? '';
        $outcome     = $this->container->make(ChallengeGateway::class)->verify($caller->context(), $factor, $binding, $challengeId, $submission->code() ?? '');
        $reason      = $outcome->reason;

        return match (true) {
            $reason === null  => CheckOutcome::passed(ObservedProperties::none(), $challengeId),
            $outcome->counted => CheckOutcome::failed($reason, $outcome->detail),
            default           => CheckOutcome::refused($reason, $outcome->detail, $outcome->lockedUntil),
        };
    }

    /**
     * The refusal of an attempt that never reached its check: a lockout or a
     * factor no longer stored.
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
