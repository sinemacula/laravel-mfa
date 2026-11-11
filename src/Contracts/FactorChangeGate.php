<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest;

/**
 * Judges freshness for a factor change under the identity's lock (lock your own
 * rows after it); a factor never counts towards its own removal.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface FactorChangeGate
{
    /**
     * Hold the session to the request's requirement too; a grant needs a future
     * end, and a refusal throws so the change rolls back.
     *
     * @param  \SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest  $request
     * @return ?\Carbon\CarbonImmutable
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    public function authorize(FactorChangeRequest $request): ?CarbonImmutable;
}
