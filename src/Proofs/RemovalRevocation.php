<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Proofs;

/**
 * What the bound `SessionRevoker` did when a factor was removed: whether it
 * judged the current session again itself, returning it to pending or ending it
 * as its own rules say, so the package hands no shortfall to the bound
 * `SessionTransition` as well; and what it returns to the caller, opaque to
 * this package, such as an authentication layer's result carrying the pending
 * session's new credential.
 *
 * The completion may hold a credential, so it is held as a
 * `\SensitiveParameterValue` and read through `completion()`, and no dump shows
 * it.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RemovalRevocation
{
    /** @var \SensitiveParameterValue What the revoker returns to the caller, hidden from dumps. */
    private \SensitiveParameterValue $completion;

    /**
     * Constructor.
     *
     * @param  bool  $judgedCurrent
     * @param  ?object  $completion
     */
    private function __construct(

        /** Whether the revoker judged the current session again itself. */
        public bool $judgedCurrent,

        // What the revoker returns to the caller, opaque to this package.
        #[\SensitiveParameter]
        ?object $completion,
    ) {
        $this->completion = new \SensitiveParameterValue($completion);
    }

    /**
     * The identity's other sessions were ended, and the current one is left to
     * the package to judge again.
     *
     * @return self
     */
    public static function othersEnded(): self
    {
        return new self(false, null);
    }

    /**
     * The identity's other sessions were ended and the current one judged again
     * by the revoker, with what it returns to the caller.
     *
     * @param  ?object  $completion
     * @return self
     */
    public static function judged(#[\SensitiveParameter] ?object $completion = null): self
    {
        return new self(true, $completion);
    }

    /**
     * What the revoker returns to the caller, or `null`.
     *
     * @return ?object
     */
    public function completion(): ?object
    {
        /** @var ?object */
        return $this->completion->getValue();
    }
}
