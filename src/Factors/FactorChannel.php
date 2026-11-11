<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Factors;

use Illuminate\Support\Str;
use SineMacula\Laravel\Mfa\Assurance\Channel;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;

/**
 * The channel a factor's proof travels on, named by its destination, its
 * passkey credential, or the factor itself.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class FactorChannel
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Enums\ChannelKind  $kind
     * @return ?\SineMacula\Laravel\Mfa\Assurance\Channel
     *
     * @throws \InvalidArgumentException
     */
    public static function of(Factor $factor, ChannelKind $kind): ?Channel
    {
        $identifier = $factor->getFactorIdentifier();

        if (!$kind->carriesFactor() || (!is_string($identifier) && !is_int($identifier))) {
            return null;
        }

        return new Channel($kind, $factor->getDestination() ?? $factor->getCredentialReference() ?? (string) $identifier);
    }

    /**
     * For a factor not yet stored: without a destination, a reference no other
     * channel shares, as its id will be.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\ChannelKind  $kind
     * @param  ?string  $destination
     * @return \SineMacula\Laravel\Mfa\Assurance\Channel
     *
     * @throws \InvalidArgumentException
     */
    public static function prospective(ChannelKind $kind, #[\SensitiveParameter] ?string $destination): Channel
    {
        return new Channel($kind, $destination ?? (string) Str::ulid());
    }
}
