<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Drivers;

use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Contracts\FactorDriver;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\CodeCheck;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;

/**
 * A passkey is proved by a WebAuthn assertion through
 * `Passkeys\PasskeyAssertions`, so this driver refuses every code.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class PasskeyDriver implements FactorDriver
{
    /**
     * @return \SineMacula\Laravel\Mfa\Enums\ChannelKind
     */
    #[\Override]
    public function channelKind(): ChannelKind
    {
        return ChannelKind::PASSKEY;
    }

    /**
     * None: they depend on what the assertion observed.
     *
     * @return list<string>
     */
    #[\Override]
    public function amr(): array
    {
        return [];
    }

    /**
     * The authentication layer registers a passkey.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @return null
     */
    #[\Override]
    public function startEnrollment(Factor $factor): null
    {
        return null;
    }

    /**
     * Its registration confirms a passkey, never a code.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  string  $code
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return \SineMacula\Laravel\Mfa\Enums\CodeCheck
     */
    #[\Override]
    public function confirm(Factor $factor, #[\SensitiveParameter] string $code, ProofBinding $binding): CodeCheck
    {
        return CodeCheck::INVALID;
    }

    /**
     * An assertion proves a passkey, never a code.
     *
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
