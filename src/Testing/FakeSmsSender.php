<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing;

use SineMacula\Laravel\Mfa\Contracts\SmsSender;
use SineMacula\Laravel\Mfa\Testing\Concerns\RecordsCodeMessages;

/**
 * Test SMS sender that keeps each code message instead of delivering it.
 * `fake()` binds it; drivers are rebuilt per call, so earlier ones use it too.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class FakeSmsSender implements SmsSender
{
    use RecordsCodeMessages;

    /** @var class-string The contract the fake is bound as. */
    public const string SENDER = SmsSender::class;
}
