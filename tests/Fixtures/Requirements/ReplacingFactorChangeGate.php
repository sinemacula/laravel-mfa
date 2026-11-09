<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Requirements;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Contracts\FactorChangeGate;
use SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest;

/**
 * A factor change gate that allows every change, and the first time it is asked
 * replaces the identity's sign-in, as another request signing the identity in
 * again would between the operation's check of its sign-in and its read of that
 * sign-in's proofs.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ReplacingFactorChangeGate implements FactorChangeGate
{
    /** @var bool Whether the sign-in has been replaced yet. */
    private bool $replaced = false;

    /**
     * Constructor.
     *
     * @param  \Closure(\SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest): void  $replace
     */
    public function __construct(

        /** Replaces the identity's sign-in, once. */
        private readonly \Closure $replace,
    ) {}

    /**
     * Replace the sign-in the first time, then allow the change.
     *
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
