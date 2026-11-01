<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Secrets;

/**
 * An exception whose context, as Laravel's exception handler logs it, carries a
 * secret and a code.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SecretCarryingException extends \RuntimeException
{
    /**
     * Constructor.
     *
     * @param  string  $secret
     * @param  string  $deliveredCode
     */
    public function __construct(

        /** The secret the context carries. */
        private readonly string $secret,

        /** The code the context carries. */
        private readonly string $deliveredCode,
    ) {
        parent::__construct('Verification failed.');
    }

    /**
     * The context Laravel's exception handler logs with the exception.
     *
     * @return array<string, string>
     */
    public function context(): array
    {
        return ['secret' => $this->secret, 'code' => $this->deliveredCode, 'factor_type' => 'totp'];
    }
}
