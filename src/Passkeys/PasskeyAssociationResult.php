<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Passkeys;

use SineMacula\Laravel\Mfa\Factors\FactorSummary;

/**
 * What associating a registered passkey as a factor made: the factor, as a
 * summary, and the recovery codes generated with it when it is the identity's
 * first additional factor, as secrets the caller reveals in its response only
 * once its own change has committed.
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
     */
    public function __construct(

        /** The passkey factor, confirmed by its registration. */
        public FactorSummary $factor,

        /** The recovery codes made with it: none unless it is the first. */
        public array $recoveryCodes = [],
    ) {}
}
