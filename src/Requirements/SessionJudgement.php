<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Requirements;

/**
 * How the session was judged again after a factor change; the completion may
 * hold a credential, so it is hidden from dumps.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SessionJudgement
{
    /** @var \SensitiveParameterValue What the transition returned, hidden from dumps. */
    private \SensitiveParameterValue $completion;

    /**
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $outstanding
     * @param  ?object  $completion
     */
    public function __construct(

        /** The requirement the session no longer meets, or `null`. */
        public ?Requirement $outstanding,

        // What the transition returned, opaque to this package.
        #[\SensitiveParameter]
        ?object $completion = null,
    ) {
        $this->completion = new \SensitiveParameterValue($completion);
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
