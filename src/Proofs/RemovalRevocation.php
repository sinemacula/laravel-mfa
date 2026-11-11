<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Proofs;

/**
 * What the bound `SessionRevoker` did on a factor removal; the completion may
 * hold a credential, so it is hidden from dumps.
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
     * @param  bool  $judgedCurrent
     * @param  ?object  $completion
     */
    private function __construct(

        /** Whether the revoker judged the current session itself. */
        public bool $judgedCurrent,

        // What the revoker returns to the caller, opaque to this package.
        #[\SensitiveParameter]
        ?object $completion,
    ) {
        $this->completion = new \SensitiveParameterValue($completion);
    }

    /**
     * Other sessions ended; the package judges the current one.
     *
     * @return self
     */
    public static function othersEnded(): self
    {
        return new self(false, null);
    }

    /**
     * Other sessions ended and the current one judged by the revoker, so the
     * package hands no shortfall to `SessionTransition`.
     *
     * @param  ?object  $completion
     * @return self
     */
    public static function judged(#[\SensitiveParameter] ?object $completion = null): self
    {
        return new self(true, $completion);
    }

    /**
     * @return ?object
     */
    public function completion(): ?object
    {
        /** @var ?object */
        return $this->completion->getValue();
    }
}
