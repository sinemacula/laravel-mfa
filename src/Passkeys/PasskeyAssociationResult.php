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
 * made of that session, whose completion, too, leaves only then.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final readonly class PasskeyAssociationResult
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Mfa\Factors\FactorSummary  $factor
     * @param  list<\SineMacula\Laravel\Mfa\Secrets\RevealedSecret>  $recoveryCodes
     * @param  ?\SineMacula\Laravel\Mfa\Verification\VerificationResult  $verification
     */
    public function __construct(

        /** The passkey factor, confirmed by its registration. */
        public FactorSummary $factor,

        /** The recovery codes made with it: none unless it is the first. */
        public array $recoveryCodes = [],

        /** What the new proof made of a pending session; none on an active one. */
        public ?VerificationResult $verification = null,
    ) {}
}
