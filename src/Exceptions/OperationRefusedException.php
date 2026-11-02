<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Exceptions;

use SineMacula\Laravel\Mfa\Enums\FailureReason;

/**
 * Operation refused exception.
 *
 * Thrown by `Factors\OperationGuard` when an operation may not go ahead: the
 * identity is a machine or inactive, the factor is not the identity's, it is
 * not confirmed where the operation needs it to be, or its type is not enabled
 * for the application. It carries the machine-readable reason the operation
 * answers with, and an internal detail for logs only; neither names another
 * identity's factor.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class OperationRefusedException extends \RuntimeException
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     * @param  string  $detail
     */
    public function __construct(

        /** The machine-readable reason the operation was refused. */
        public readonly FailureReason $reason,

        // What happened in detail, for logs only.
        string $detail,
    ) {
        parent::__construct($detail);
    }

    /**
     * Refuse the operation for the reason, with the detail, unless it is
     * allowed.
     *
     * @param  bool  $allowed
     * @param  \SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     * @param  string  $detail
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     *
     * @phpstan-assert true $allowed
     */
    public static function unless(bool $allowed, FailureReason $reason, string $detail): void
    {
        if (!$allowed) {
            throw new self($reason, $detail);
        }
    }
}
