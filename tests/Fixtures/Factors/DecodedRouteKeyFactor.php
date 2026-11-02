<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Factors;

use SineMacula\Laravel\Mfa\Concerns\ResolvesFactorRouteBinding;

/**
 * A factor model that binds through the caller over a base model's own route
 * binding, so the base's lookup is shown to be the one that runs.
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
