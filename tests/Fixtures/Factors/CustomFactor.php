<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Factors;

use SineMacula\Laravel\Mfa\Models\Factor;

/**
 * An application's subclass of the shipped `Factor` model, bound through
 * `mfa.factor.model`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class CustomFactor extends Factor
{
    /** @var string Identifies this subclass in assertions. */
    public const string FIXTURE_TAG = 'custom-factor-fixture';
}
