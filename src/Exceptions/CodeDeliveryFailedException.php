<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Exceptions;

use SineMacula\Laravel\Mfa\Factors\FactorSummary;

/**
 * Thrown when a driver or its sender fails to deliver a code. The previous
 * exception is scrubbed and the destination masked, so neither reaches a log.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class CodeDeliveryFailedException extends \RuntimeException
{
    /**
     * @param  \SineMacula\Laravel\Mfa\Factors\FactorSummary  $factor
     * @param  \Throwable  $previous
     */
    public function __construct(

        /** The destination is masked. */
        public readonly FactorSummary $factor,

        // Already scrubbed of the code and destination.
        \Throwable $previous,
    ) {
        $destination = $factor->maskedDestination === null ? '' : ' at ' . $factor->maskedDestination;

        parent::__construct(sprintf('The code could not be delivered to the %s factor%s.', $factor->type, $destination), 0, $previous);
    }
}
