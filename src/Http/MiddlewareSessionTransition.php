<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Http;

use SineMacula\Laravel\Mfa\Contracts\SessionTransition;
use SineMacula\Laravel\Mfa\Requirements\SessionChange;

/**
 * Default `SessionTransition`: changes nothing, because the `mfa` middleware
 * judges the whole requirement afresh on every request and asks for what is
 * lacking.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class MiddlewareSessionTransition implements SessionTransition
{
    /**
     * @param  \SineMacula\Laravel\Mfa\Requirements\SessionChange  $change
     * @return null
     */
    #[\Override]
    public function factorChanged(SessionChange $change): null
    {
        return null;
    }
}
