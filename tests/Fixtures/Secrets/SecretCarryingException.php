<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Secrets;

/**
 * An exception whose logged context carries a secret and a code.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SecretCarryingException extends \RuntimeException
{
    /**
     * @param  string  $secret
     * @param  string  $deliveredCode
     */
    public function __construct(

        /** @var string */
        private readonly string $secret,

        /** @var string */
        private readonly string $deliveredCode,
    ) {
        parent::__construct('Verification failed.');
    }

    /**
     * Logged by Laravel's exception handler with the exception.
     *
     * @return array<string, string>
     */
    public function context(): array
    {
        return ['secret' => $this->secret, 'code' => $this->deliveredCode, 'factor_type' => 'totp'];
    }
}
