<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Applications;

use SineMacula\Laravel\Mfa\Enums\ChannelKind;

/**
 * The first factor an application declares its guard uses, so the combination
 * policy can accept a further factor without an authentication layer.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class DeclaredFirstFactor
{
    /**
     * @param  string  $method
     * @param  \SineMacula\Laravel\Mfa\Enums\ChannelKind  $channel
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** Such as `password`. */
        public string $method,

        /** Never unknown. */
        public ChannelKind $channel,
    ) {
        if (trim($method) === '') {
            throw new \InvalidArgumentException('The method of a declared first factor must not be blank.');
        }

        if ($channel === ChannelKind::UNKNOWN) {
            throw new \InvalidArgumentException('The channel of a declared first factor must be known.');
        }
    }
}
