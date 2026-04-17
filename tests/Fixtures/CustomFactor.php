<?php

declare(strict_types = 1);

namespace Tests\Fixtures;

use SineMacula\Laravel\Mfa\Models\Factor;

/**
 * Consumer-style subclass of the shipped `Factor` model.
 *
 * Used by the configurable-factor-model integration test to prove that
 * `Mfa::factorModel()` honours `config('mfa.factor.model')` and that the
 * package never instantiates the shipped Factor when the consumer has bound a
 * different class.
 *
 * Carries a public sentinel constant so tests can assert resolution was
 * honoured without monkeying with class introspection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class CustomFactor extends Factor
{
    /** @var string Sentinel string used in tests to identify this subclass. */
    public const string FIXTURE_TAG = 'custom-factor-fixture';
}
