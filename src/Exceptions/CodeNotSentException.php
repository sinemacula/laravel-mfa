<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Exceptions;

use SineMacula\Laravel\Mfa\Codes\SendResult;

/**
 * Carries an unsent first enrolment code out of the factor state transaction,
 * so the pending factor and its grant roll back.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class CodeNotSentException extends \RuntimeException
{
    /**
     * @param  \SineMacula\Laravel\Mfa\Codes\SendResult  $result
     */
    public function __construct(

        /** Why no code was sent, and how long to wait. */
        public readonly SendResult $result,
    ) {
        parent::__construct('The enrolment\'s first code was not sent.');
    }
}
