<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Drivers;

use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Contracts\FactorDriver;
use SineMacula\Laravel\Mfa\Enums\CodeCheck;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use Tests\Fixtures\Drivers\Concerns\DescribesNoChannel;

/**
 * A driver to register where its behaviour does not matter.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class NoopFactorDriver implements FactorDriver
{
    use DescribesNoChannel;

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  string  $code
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return \SineMacula\Laravel\Mfa\Enums\CodeCheck
     */
    #[\Override]
    public function verify(Factor $factor, #[\SensitiveParameter] string $code, ProofBinding $binding): CodeCheck
    {
        return CodeCheck::INVALID;
    }
}
