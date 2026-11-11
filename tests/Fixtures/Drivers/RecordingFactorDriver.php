<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Drivers;

use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Contracts\FactorDriver;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\CodeCheck;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use Tests\Fixtures\Drivers\Concerns\DescribesNoChannel;

/**
 * Counts verify calls, accepts `correct` and reports `replayed` as a replay.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecordingFactorDriver implements FactorDriver
{
    use DescribesNoChannel;

    /** @var int */
    public int $verifyCalls = 0;

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  string  $code
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return \SineMacula\Laravel\Mfa\Enums\CodeCheck
     */
    #[\Override]
    public function verify(Factor $factor, #[\SensitiveParameter] string $code, ProofBinding $binding): CodeCheck
    {
        $this->verifyCalls++;

        return match ($code) {
            'correct'  => CodeCheck::ACCEPTED,
            'replayed' => CodeCheck::REPLAYED,
            default    => CodeCheck::INVALID,
        };
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Enums\ChannelKind
     */
    #[\Override]
    public function channelKind(): ChannelKind
    {
        return ChannelKind::AUTHENTICATOR_APP;
    }

    /**
     * Includes `mfa`, which the result must leave out.
     *
     * @return list<string>
     */
    #[\Override]
    public function amr(): array
    {
        return ['otp', 'mfa', 'custom'];
    }
}
