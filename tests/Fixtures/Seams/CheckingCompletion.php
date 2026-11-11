<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Seams;

use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Contracts\PendingCompletion;
use SineMacula\Laravel\Mfa\Contracts\StepUp;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Verification\VerificationResult;

/**
 * Accepts only a result bound to the expected session, or every result when it
 * does not check.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class CheckingCompletion implements PendingCompletion, StepUp
{
    /** @var list<\SineMacula\Laravel\Mfa\Verification\VerificationResult> */
    public array $accepted = [];

    /** @var list<\SineMacula\Laravel\Mfa\Context\CallerContext> The callers each completion was handed. */
    public array $callers = [];

    /**
     * @param  string  $session
     * @param  bool  $checks
     * @param  ?object  $completion
     */
    public function __construct(

        /** The session a step-up result must be bound to. */
        private readonly string $session,

        /** Whether results are checked at all. */
        private readonly bool $checks = true,

        /** Returned for an accepted result. */
        private readonly ?object $completion = null,
    ) {}

    /**
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  \SineMacula\Laravel\Mfa\Verification\VerificationResult  $result
     * @return ?object
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    #[\Override]
    public function complete(CallerContext $caller, VerificationResult $result): ?object
    {
        $this->callers[] = $caller;

        return $this->accept($result, $caller->pending->sessionId ?? '');
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  \SineMacula\Laravel\Mfa\Verification\VerificationResult  $result
     * @return ?object
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    #[\Override]
    public function stepUp(CallerContext $caller, VerificationResult $result): ?object
    {
        return $this->accept($result, $this->session);
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Verification\VerificationResult  $result
     * @param  string  $session
     * @return ?object
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    private function accept(VerificationResult $result, string $session): ?object
    {
        if ($this->checks && $result->proof?->binding->sessionId !== $session) {
            throw new OperationRefusedException(FailureReason::NOT_ACCEPTED, 'The result is not bound to the session.');
        }

        $this->accepted[] = $result;

        return $this->completion;
    }
}
