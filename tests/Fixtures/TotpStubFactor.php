<?php

declare(strict_types = 1);

namespace Tests\Fixtures;

/**
 * `Factor` fixture exposing a configurable stored secret against the TOTP
 * driver — feeds the verify branches without persistence.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class TotpStubFactor extends AbstractFactorStub
{
    /**
     * Capture the seeded secret value.
     *
     * @param  ?string  $secret
     * @return void
     */
    public function __construct(

        /** Stored TOTP shared secret. */
        #[\SensitiveParameter]
        private readonly ?string $secret,

    ) {}

    /**
     * @return mixed
     */
    public function getFactorIdentifier(): mixed
    {
        return 'totp-stub';
    }

    /**
     * @return string
     */
    public function getDriver(): string
    {
        return 'totp';
    }

    /**
     * @return ?string
     */
    public function getSecret(): ?string
    {
        return $this->secret;
    }
}
