<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing;

use SineMacula\Laravel\Mfa\Contracts\EmailSender;
use SineMacula\Laravel\Mfa\Testing\Concerns\RecordsCodeMessages;

/**
 * Test email sender that keeps each code message instead of delivering it.
 * `fake()` binds it; drivers are rebuilt per call, so earlier ones use it too.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class FakeEmailSender implements EmailSender
{
    use RecordsCodeMessages;

    /** @var class-string The contract the fake is bound as. */
    public const string SENDER = EmailSender::class;
}
