<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Testing;

use SineMacula\Laravel\Mfa\Codes\MfaCodeMessage;

/**
 * A code message that always chooses its own locale, as a subclass may.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ExplicitLocaleCodeMessage extends MfaCodeMessage
{
    /**
     * Constructor.
     *
     * @param  string  $code
     * @param  int  $expiresInMinutes
     */
    public function __construct(#[\SensitiveParameter] string $code, int $expiresInMinutes)
    {
        parent::__construct($code, $expiresInMinutes);

        $this->locale('de');
    }
}
