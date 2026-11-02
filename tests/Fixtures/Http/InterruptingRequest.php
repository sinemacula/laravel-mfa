<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Http;

use Illuminate\Http\Request;

/**
 * A request that runs a callback when its IP address is read, which a
 * verification does just before it takes the identity's lock, so a test can
 * make a concurrent change at that moment.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class InterruptingRequest extends Request
{
    /** @var (\Closure(): void)|null What to run when the address is read. */
    public ?\Closure $interruption = null;

    /**
     * Run the interruption, then answer as any request does.
     *
     * @return ?string
     */
    #[\Override]
    public function ip(): ?string
    {
        if ($this->interruption !== null) {
            ($this->interruption)();
        }

        return parent::ip();
    }
}
