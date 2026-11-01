<?php

declare(strict_types = 1);

namespace Tests\Unit\Concerns;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Assurance\Channel;
use SineMacula\Laravel\Mfa\Assurance\ObservedProperties;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;

/**
 * Builds a valid additional-factor proof for the tests of the values that hold
 * one, with any argument overridden by name.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait BuildsProofs
{
    /**
     * Build a TOTP proof made on a step-up, with the given arguments in place
     * of the defaults.
     *
     * @param  array<string, mixed>  $overrides
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     */
    protected static function proof(array $overrides = []): Proof
    {
        /** @phpstan-ignore argument.type (the overrides are named arguments of the constructor) */
        return new Proof(...array_merge([
            'kind'        => ProofKind::ADDITIONAL_FACTOR,
            'method'      => 'totp',
            'channel'     => new Channel(ChannelKind::AUTHENTICATOR_APP, 'factor-1'),
            'reference'   => 'factor-1',
            'properties'  => ObservedProperties::none(),
            'provedAt'    => CarbonImmutable::parse('2026-11-01T09:30:15.123456+00:00'),
            'binding'     => new ProofBinding('user', '42', 'admin', 'session-1', Purpose::STEP_UP),
            'generation'  => 3,
            'challengeId' => null,
        ], $overrides));
    }
}
