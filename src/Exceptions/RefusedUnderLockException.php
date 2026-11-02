<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Exceptions;

/**
 * Refused under lock exception.
 *
 * Carries an `OperationRefusedException` out of the identity's factor state
 * transaction, so what the transaction did rolls back and the entry point turns
 * the refusal into a failed result. A refusal thrown after the commit, by a
 * listener of an event the transaction queued, is not one of these, so it
 * propagates: what committed stays committed and is never reported as failed.
 *
 * It also carries the challenge a check reported before the refusal, which the
 * failure's event names.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RefusedUnderLockException extends \RuntimeException
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException  $refusal
     * @param  ?string  $challengeId
     */
    public function __construct(

        /** The refusal, with the reason a caller may be told. */
        public readonly OperationRefusedException $refusal,

        /** The challenge a check reported before the refusal, when one did. */
        public readonly ?string $challengeId = null,
    ) {
        parent::__construct('The operation was refused under the identity\'s lock.', 0, $refusal);
    }

    /**
     * Run the work, which is inside the transaction, carrying out any refusal
     * it throws.
     *
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
