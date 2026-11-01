<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Applications;

use SineMacula\Laravel\Mfa\Enums\ChannelKind;

/**
 * The first factor an application declares its guard signs people in with, when
 * no authentication layer reports it: the method and the kind of channel it
 * proves. Without an authentication layer, a declaration (or a bound
 * `FirstFactorResolver`) is what lets the combination policy accept a further
 * factor; a channel the application cannot name is no declaration at all.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class DeclaredFirstFactor
{
    /**
     * Constructor.
     *
     * @param  string  $method
     * @param  \SineMacula\Laravel\Mfa\Enums\ChannelKind  $channel
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The method the guard signs people in with, such as `password`. */
        public string $method,

        /** The kind of channel that method proves. */
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
