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
 * Custom `FactorDriver` fixture that records verify calls and accepts
 * `'correct'` as the only valid code.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecordingFactorDriver implements FactorDriver
{
    use DescribesNoChannel;

    /** @var int Verify call counter for the test assertions. */
    public int $verifyCalls = 0;

    /**
     * Record the verify call and report success only when the submitted code is
     * the magic string `'correct'`, and a replay for `'replayed'`.
     *
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
     * Report an additional factor on an authenticator's channel with an `mfa`
     * value the result must leave out.
     *
     * @return \SineMacula\Laravel\Mfa\Enums\ChannelKind
     */
    #[\Override]
    public function channelKind(): ChannelKind
    {
        return ChannelKind::AUTHENTICATOR_APP;
    }

    /**
     * The `amr` values the driver claims, `mfa` among them.
     *
     * @return list<string>
     */
    #[\Override]
    public function amr(): array
    {
        return ['otp', 'mfa', 'custom'];
    }
}
