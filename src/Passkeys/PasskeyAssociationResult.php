<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Passkeys;

use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use SineMacula\Laravel\Mfa\Verification\VerificationResult;

/**
 * What associating a registered passkey as a factor made: the factor, as a
 * summary; the recovery codes generated with it when it is the identity's first
 * additional factor, as secrets the caller reveals in its response only once
 * its own change has committed; and, on a pending session, what its new proof
 * made of that session or, on an active one, what the bound `SessionTransition`
 * returned for the caller, either completion, too, leaving only then.
 *
 * The completion may hold a credential, so it is held as a
 * `\SensitiveParameterValue` and read through `completion()`, and no dump shows
 * it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final readonly class PasskeyAssociationResult
{
    /** @var \SensitiveParameterValue What the session transition returned, hidden from dumps. */
    private \SensitiveParameterValue $completion;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Mfa\Factors\FactorSummary  $factor
     * @param  list<\SineMacula\Laravel\Mfa\Secrets\RevealedSecret>  $recoveryCodes
     * @param  ?\SineMacula\Laravel\Mfa\Verification\VerificationResult  $verification
     * @param  ?object  $completion
     */
    public function __construct(

        /** The passkey factor, confirmed by its registration. */
        public FactorSummary $factor,

        /** The recovery codes made with it: none unless it is the first. */
        public array $recoveryCodes = [],

        /** What the new proof made of a pending session; none on an active one. */
        public ?VerificationResult $verification = null,

        // What the session transition returned on an active session, opaque to
        // this package.
        #[\SensitiveParameter]
        ?object $completion = null,
    ) {
        $this->completion = new \SensitiveParameterValue($completion);
    }

    /**
     * What the bound session transition returned for the caller on an active
     * session, such as a pending session's new credential, or `null`; on a
     * pending session the verification's `completion()` is the one.
     *
     * @return ?object
     */
    public function completion(): ?object
    {
        /** @var ?object */
        return $this->completion->getValue();
    }
}
