<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Factors;

use SineMacula\Laravel\Mfa\Assurance\Channel;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;

/**
 * The channel a factor's proof travels on: the kind its driver states, naming
 * the factor's destination when it has one, the passkey credential it is
 * associated with when it has one, and the factor itself otherwise. A kind that
 * cannot carry a factor, or a factor whose identifier cannot name it, has no
 * channel.
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
     * The factor's channel of the given kind, or `null` when it has none.
     *
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
}
