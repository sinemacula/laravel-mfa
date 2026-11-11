<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Factors;

use SineMacula\Laravel\Mfa\Models\Factor;

/**
 * A factor model whose persistence seam neither writes the row nor throws.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class UnwrittenFactor extends Factor
{
    /**
     * @return void
     */
    #[\Override]
    public function persist(): void {}
}
