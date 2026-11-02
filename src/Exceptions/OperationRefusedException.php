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
 * A seam may throw one too. On `generateRecoveryCodes()` and
 * `requestAssertion()` that stays an exception: only a refusal marked as the
 * package's own becomes the value there, so a seam's is never read as the
 * package deciding. The other helpers that answer with a value, such as
 * `sendCode()` and `verify()`, do not read the mark, and report it as their
 * reason. The mark says who refused, not when.
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
     * @param  bool  $byPackage
     */
    public function __construct(

        /** The machine-readable reason the operation was refused. */
        public readonly FailureReason $reason,

        // What happened in detail, for logs only.
        string $detail,

        /** Whether the package itself refused: see `byPackage()`. */
        public readonly bool $byPackage = false,
    ) {
        parent::__construct($detail);
    }

    /**
     * A refusal the package itself makes.
     *
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
     * Refuse the operation for the reason, with the detail, unless it is
     * allowed, as `unless()` does, and as the package's own refusal.
     *
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
