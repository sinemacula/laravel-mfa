<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Passkeys;

use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use SineMacula\Laravel\Mfa\Verification\VerificationResult;

/**
 * What associating a passkey as a factor made. Reveal the recovery codes and
 * the completion only once the caller's own change has committed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final readonly class PasskeyAssociationResult
{
    /** @var \SensitiveParameterValue Hidden from dumps, as it may hold a credential. */
    private \SensitiveParameterValue $completion;

    /**
     * @param  \SineMacula\Laravel\Mfa\Factors\FactorSummary  $factor
     * @param  list<\SineMacula\Laravel\Mfa\Secrets\RevealedSecret>  $recoveryCodes
     * @param  ?\SineMacula\Laravel\Mfa\Verification\VerificationResult  $verification
     * @param  ?object  $completion
     */
    public function __construct(

        /** The passkey factor, confirmed by its registration. */
        public FactorSummary $factor,

        /** None unless it is the first additional factor. */
        public array $recoveryCodes = [],

        /** Null on an active session. */
        public ?VerificationResult $verification = null,

        // What the session transition returned on an active session.
        #[\SensitiveParameter]
        ?object $completion = null,
    ) {
        $this->completion = new \SensitiveParameterValue($completion);
    }

    /**
     * The active session's completion; on a pending session use the
     * verification's `completion()`.
     *
     * @return ?object
     */
    public function completion(): ?object
    {
        /** @var ?object */
        return $this->completion->getValue();
    }
}
