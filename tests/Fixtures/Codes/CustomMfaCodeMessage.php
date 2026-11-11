<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Codes;

use SineMacula\Laravel\Mfa\Codes\MfaCodeMessage;

/**
 * A mailable subclass for the email driver's `$mailable` argument.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class CustomMfaCodeMessage extends MfaCodeMessage {}
