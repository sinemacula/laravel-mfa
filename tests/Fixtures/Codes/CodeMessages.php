<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Codes;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Codes\CodeMessage;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use SineMacula\Laravel\Mfa\Secrets\RevealedSecret;
use Tests\Fixtures\Factors\InMemoryFactor;
use Tests\Fixtures\Identities\NonEloquentIdentity;

/**
 * Code messages as the code service builds them for a factor.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class CodeMessages
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * A sign-in code message on `web`, expiring in ten minutes by default.
     *
     * @param  string  $destination
     * @param  string  $code
     * @param  ?\Carbon\CarbonImmutable  $expiresAt
     * @param  string  $type
     * @param  \SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @param  ?\SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $recipient
     * @return \SineMacula\Laravel\Mfa\Codes\CodeMessage
     */
    public static function to(
        string $destination,
        string $code = '123456',
        ?CarbonImmutable $expiresAt = null,
        string $type = 'email',
        Purpose $purpose = Purpose::SIGN_IN,
        ?MultiFactorAuthenticatable $recipient = null,
    ): CodeMessage {
        return new CodeMessage(
            application: 'web',
            purpose    : $purpose,
            type       : $type,
            destination: $destination,
            code       : new RevealedSecret($code),
            expiresAt  : $expiresAt ?? CarbonImmutable::now()->addMinutes(10),
            recipient  : $recipient ?? new NonEloquentIdentity('identity-1'),
            factor     : FactorSummary::fromFactor(new InMemoryFactor(type: $type, destination: $destination)),
        );
    }
}
