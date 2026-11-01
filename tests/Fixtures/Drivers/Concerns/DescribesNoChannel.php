<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Drivers\Concerns;

use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;

/**
 * The parts of the `FactorDriver` contract a test driver rarely needs: an
 * unknown channel, no `amr` values, no secret to start an enrolment with, and
 * confirmation checked as verification.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait DescribesNoChannel
{
    /**
     * An unknown channel.
     *
     * @return \SineMacula\Laravel\Mfa\Enums\ChannelKind
     */
    public function channelKind(): ChannelKind
    {
        return ChannelKind::UNKNOWN;
    }

    /**
     * No `amr` values.
     *
     * @return list<string>
     */
    public function amr(): array
    {
        return [];
    }

    /**
     * No secret to start an enrolment with.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @return ?string
     */
    public function startEnrollment(Factor $factor): ?string
    {
        return null;
    }

    /**
     * Confirmation checked as verification.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  string  $code
     * @return bool
     *
     * @imperative
     */
    public function confirm(Factor $factor, #[\SensitiveParameter] string $code): bool
    {
        return $this->verify($factor, $code);
    }

    /**
     * Verify the code against the factor.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  string  $code
     * @return bool
     */
    abstract public function verify(Factor $factor, #[\SensitiveParameter] string $code): bool;
}
