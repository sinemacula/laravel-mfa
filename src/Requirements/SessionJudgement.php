<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Requirements;

/**
 * How the current session was judged again after a change to the identity's
 * factors: the package's own assessment, the requirement the session no longer
 * meets, or `null` when it meets it; and what the bound `SessionTransition`
 * returned for the caller, opaque to this package.
 *
 * The completion may hold a credential, so it is held as a
 * `\SensitiveParameterValue` and read through `completion()`, and no dump shows
 * it.
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
     * Constructor.
     *
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $outstanding
     * @param  ?object  $completion
     */
    public function __construct(

        /** The requirement the session no longer meets, whole, or `null` when it meets it. */
        public ?Requirement $outstanding,

        // What the transition returned, opaque to this package.
        #[\SensitiveParameter]
        ?object $completion = null,
    ) {
        $this->completion = new \SensitiveParameterValue($completion);
    }

    /**
     * What the transition returned for the caller, or `null`.
     *
     * @return ?object
     */
    public function completion(): ?object
    {
        /** @var ?object */
        return $this->completion->getValue();
    }
}
