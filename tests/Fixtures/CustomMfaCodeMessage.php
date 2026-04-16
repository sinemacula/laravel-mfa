<?php

declare(strict_types = 1);

namespace Tests\Fixtures;

use SineMacula\Laravel\Mfa\Mail\MfaCodeMessage;

/**
 * Custom Mailable subclass used to verify the constructor-configurable
 * `$mailable` class argument is honoured by the email driver.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class CustomMfaCodeMessage extends MfaCodeMessage {}
