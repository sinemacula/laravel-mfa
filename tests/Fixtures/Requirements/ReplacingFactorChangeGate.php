<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Requirements;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Contracts\FactorChangeGate;
use SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest;

/**
 * Allows every change and, on the first call, replaces the sign-in as a
 * concurrent sign-in would between the check and the read of its proofs.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ReplacingFactorChangeGate implements FactorChangeGate
{
    /** @var bool */
    private bool $replaced = false;

    /**
     * @param  \Closure(\SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest): void  $replace
     */
    public function __construct(

        /** Replaces the identity's sign-in, once. */
        private readonly \Closure $replace,
    ) {}

    /**
     * @param  \SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest  $request
     * @return ?\Carbon\CarbonImmutable
     */
    #[\Override]
    public function authorize(FactorChangeRequest $request): ?CarbonImmutable
    {
        if (!$this->replaced) {
            $this->replaced = true;

            ($this->replace)($request);
        }

        return null;
    }
}
