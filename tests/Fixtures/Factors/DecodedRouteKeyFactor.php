<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Factors;

use SineMacula\Laravel\Mfa\Concerns\ResolvesFactorRouteBinding;

/**
 * Binds through the caller over a base model's own route binding, to show the
 * base's lookup is the one that runs.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpstan-ignore sineMaculaLaravel.modelBehaviour, sineMaculaLaravel.modelBehaviour
 */
final class DecodedRouteKeyFactor extends DecodedRouteKeyFactorBase
{
    use ResolvesFactorRouteBinding;
}
