<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Seams;

use SineMacula\Laravel\Mfa\Context\PendingContext;
use SineMacula\Laravel\Mfa\Contracts\PendingCompletion;
use SineMacula\Laravel\Mfa\Contracts\StepUp;
use SineMacula\Laravel\Mfa\Verification\VerificationResult;

/**
 * A pending completion and step-up that accept a successful result bound to the
 * session they expect, and refuse anything else by throwing; or, when it does
 * not check, a faulty one that accepts every result.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class CheckingCompletion implements PendingCompletion, StepUp
{
    /** @var list<\SineMacula\Laravel\Mfa\Verification\VerificationResult> The results accepted. */
    public array $accepted = [];

    /**
     * Constructor.
     *
     * @param  string  $session
     * @param  bool  $checks
     */
    public function __construct(

        /** The session an active session's result must be bound to. */
        private readonly string $session,

        /** Whether results are checked at all. */
        private readonly bool $checks = true,
    ) {}

    /**
     * Accept a successful result bound to the pending session.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\PendingContext  $pending
     * @param  \SineMacula\Laravel\Mfa\Verification\VerificationResult  $result
     * @return void
     *
     * @throws \RuntimeException
     */
    #[\Override]
    public function complete(PendingContext $pending, VerificationResult $result): void
    {
        $this->accept($result, $pending->sessionId);
    }

    /**
     * Accept a successful result bound to the active session.
     *
     * @param  \SineMacula\Laravel\Mfa\Verification\VerificationResult  $result
     * @return void
     *
     * @throws \RuntimeException
     */
    #[\Override]
    public function stepUp(VerificationResult $result): void
    {
        $this->accept($result, $this->session);
    }

    /**
     * Accept the result, refusing one that failed or is bound to another
     * session when results are checked.
     *
     * @param  \SineMacula\Laravel\Mfa\Verification\VerificationResult  $result
     * @param  string  $session
     * @return void
     *
     * @throws \RuntimeException
     */
    private function accept(VerificationResult $result, string $session): void
    {
        if ($this->checks && $result->proof?->binding->sessionId !== $session) {
            throw new \RuntimeException('The result is not bound to the session.');
        }

        $this->accepted[] = $result;
    }
}
