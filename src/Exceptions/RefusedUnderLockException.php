<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Exceptions;

/**
 * Carries a refusal out of the factor state transaction so it rolls back. A
 * refusal from a listener after commit is not wrapped, so it is never reported
 * as a failed result.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RefusedUnderLockException extends \RuntimeException
{
    /**
     * @param  \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException  $refusal
     * @param  ?string  $challengeId
     */
    public function __construct(

        /** The refusal, with the reason a caller may be told. */
        public readonly OperationRefusedException $refusal,

        /** For the failure event, when a check reported one before the refusal. */
        public readonly ?string $challengeId = null,
    ) {
        parent::__construct('The operation was refused under the identity\'s lock.', 0, $refusal);
    }

    /**
     * @template TReturn
     *
     * @param  \Closure(): TReturn  $work
     * @param  ?string  $challengeId
     * @return TReturn
     *
     * @throws self
     *
     * @param-immediately-invoked-callable $work
     */
    public static function carrying(\Closure $work, ?string $challengeId = null): mixed
    {
        try {
            return $work();
        } catch (OperationRefusedException $exception) {
            throw new self($exception, $challengeId);
        }
    }
}
