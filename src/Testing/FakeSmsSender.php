<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing;

use SineMacula\Laravel\Mfa\Contracts\SmsSender;
use SineMacula\Laravel\Mfa\Testing\Concerns\RecordsCodeMessages;

/**
 * An SMS sender for tests: keeps every code message it is given instead of
 * delivering it, so a test can read the code a request sent and verify with it,
 * and see the purpose, the application and the recipient it was sent for.
 *
 * `FakeSmsSender::fake()` binds a fresh instance as the application's sender
 * and returns it; the manager builds its drivers again, so one resolved before
 * sends through the fake too. Not for production use.
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
