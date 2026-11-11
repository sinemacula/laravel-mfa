<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Drivers\Concerns;

use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\CodeCheck;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Secrets\RevealedSecret;

/**
 * The parts of the `FactorDriver` contract a test driver rarely needs.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait DescribesNoChannel
{
    /**
     * @return \SineMacula\Laravel\Mfa\Enums\ChannelKind
     */
    public function channelKind(): ChannelKind
    {
        return ChannelKind::UNKNOWN;
    }

    /**
     * @return list<string>
     */
    public function amr(): array
    {
        return [];
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @return ?\SineMacula\Laravel\Mfa\Secrets\RevealedSecret
     */
    public function startEnrollment(Factor $factor): ?RevealedSecret
    {
        return null;
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  string  $code
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return \SineMacula\Laravel\Mfa\Enums\CodeCheck
     */
    public function confirm(Factor $factor, #[\SensitiveParameter] string $code, ProofBinding $binding): CodeCheck
    {
        return $this->verify($factor, $code, $binding);
    }
}
