<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Exceptions;

use SineMacula\Laravel\Mfa\Enums\FailureReason;

/**
 * Thrown when an operation may not go ahead. Neither the reason nor the detail
 * names another identity's factor.
 *
 * On `generateRecoveryCodes()` and `requestAssertion()` only a refusal marked
 * `byPackage` becomes a result, so a seam's refusal stays an exception.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class OperationRefusedException extends \RuntimeException
{
    /**
     * @param  \SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     * @param  string  $detail
     * @param  bool  $byPackage
     */
    public function __construct(

        /** The machine-readable reason a caller is told. */
        public readonly FailureReason $reason,

        // For logs only.
        string $detail,

        /** Who refused, not when. */
        public readonly bool $byPackage = false,
    ) {
        parent::__construct($detail);
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     * @param  string  $detail
     * @return self
     *
     * @internal
     */
    public static function byPackage(FailureReason $reason, string $detail): self
    {
        return new self($reason, $detail, true);
    }

    /**
     * @param  bool  $allowed
     * @param  \SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     * @param  string  $detail
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     *
     * @phpstan-assert true $allowed
     *
     * @internal
     */
    public static function byPackageUnless(bool $allowed, FailureReason $reason, string $detail): void
    {
        if (!$allowed) {
            throw self::byPackage($reason, $detail);
        }
    }

    /**
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
