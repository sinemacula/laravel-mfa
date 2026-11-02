<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Secrets;

use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Contracts\FactorDriver;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\CodeCheck;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use Tests\Fixtures\Drivers\Concerns\DescribesNoChannel;

/**
 * A driver outside the package that hands the code it is given to a check of
 * its own, which fails, as an application's driver whose store is down would.
 *
 * Neither method marks the code as sensitive, so PHP records it in both frames
 * of the trace.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class CodeForwardingDriver implements FactorDriver
{
    use DescribesNoChannel;

    /**
     * An authenticator app's channel, so the code reaches the driver.
     *
     * @return \SineMacula\Laravel\Mfa\Enums\ChannelKind
     */
    #[\Override]
    public function channelKind(): ChannelKind
    {
        return ChannelKind::AUTHENTICATOR_APP;
    }

    /**
     * Check the code, which fails.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  string  $code
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return \SineMacula\Laravel\Mfa\Enums\CodeCheck
     */
    #[\Override]
    public function verify(Factor $factor, string $code, ProofBinding $binding): CodeCheck
    {
        return $this->isAccepted($code) ? CodeCheck::ACCEPTED : CodeCheck::INVALID;
    }

    /**
     * Whether the code is accepted, which fails to be known.
     *
     * @param  string  $code
     * @return bool
     *
     * @throws \RuntimeException
     */
    private function isAccepted(string $code): bool
    {
        throw new \RuntimeException('The code store is unavailable for a code of ' . strlen($code) . ' characters.');
    }
}
