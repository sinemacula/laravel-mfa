<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Exceptions;

use SineMacula\Laravel\Mfa\Factors\FactorSummary;

/**
 * Code delivery failed exception.
 *
 * Thrown by the code service when a delivered factor's driver, or the sender
 * behind it, fails to deliver a code. The failure is kept as the previous
 * exception, scrubbed of the code and the full destination first (see
 * `Secrets\ExceptionScrubber`), and this exception names the factor by its
 * summary, whose destination is masked, so neither the code nor the full
 * destination reaches a log or an error report through it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class CodeDeliveryFailedException extends \RuntimeException
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Mfa\Factors\FactorSummary  $factor
     * @param  \Throwable  $previous
     */
    public function __construct(

        /** The factor the code was to be delivered to, its destination masked. */
        public readonly FactorSummary $factor,

        // The failure of the delivery, scrubbed.
        \Throwable $previous,
    ) {
        $destination = $factor->maskedDestination === null ? '' : ' at ' . $factor->maskedDestination;

        parent::__construct(sprintf('The code could not be delivered to the %s factor%s.', $factor->type, $destination), 0, $previous);
    }
}
