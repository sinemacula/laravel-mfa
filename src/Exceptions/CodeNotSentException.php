<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Exceptions;

use SineMacula\Laravel\Mfa\Codes\SendResult;

/**
 * Code not sent exception.
 *
 * Carries why an enrolment's first code was not sent out of the identity's
 * factor state transaction, so the pending factor and its grant roll back and
 * the entry point answers with the reason and how long to wait.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class CodeNotSentException extends \RuntimeException
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Mfa\Codes\SendResult  $result
     */
    public function __construct(

        /** Why no code was sent, and how long to wait. */
        public readonly SendResult $result,
    ) {
        parent::__construct('The enrolment\'s first code was not sent.');
    }
}
