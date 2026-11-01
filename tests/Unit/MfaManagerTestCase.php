<?php

declare(strict_types = 1);

namespace Tests\Unit;

use Tests\TestCase;

/**
 * Base test case for the MfaManager test family.
 *
 * Boots the same application as `Tests\TestCase`; kept as the shared parent of
 * the manager tests so they read as one family.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
abstract class MfaManagerTestCase extends TestCase {}
