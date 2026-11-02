<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Drivers;

use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Contracts\FactorDriver;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\CodeCheck;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;

/**
 * Passkey factor driver.
 *
 * A passkey is proved by a WebAuthn assertion, never by a code: its credential
 * and ceremonies are the bound `PasskeyGateway`'s, a factor exists only through
 * an association record, and its assertions are requested and verified by
 * `Passkeys\PasskeyAssertions`. The driver states the channel and refuses
 * everything a code would do. It claims no `amr` value of its own: presence,
 * user verification and the key's protection are read from what an assertion
 * observed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class PasskeyDriver implements FactorDriver
{
    /**
     * A passkey credential.
     *
     * @return \SineMacula\Laravel\Mfa\Enums\ChannelKind
     */
    #[\Override]
    public function channelKind(): ChannelKind
    {
        return ChannelKind::PASSKEY;
    }

    /**
     * None: a passkey's `amr` values depend on what its assertion observed.
     *
     * @return list<string>
     */
    #[\Override]
    public function amr(): array
    {
        return [];
    }

    /**
     * No secret: a passkey is registered by the authentication layer.
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
     * Never: a code does not confirm a passkey; its registration does.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  string  $code
     * @return bool
     *
     * @imperative
     */
    #[\Override]
    public function confirm(Factor $factor, #[\SensitiveParameter] string $code): bool
    {
        return false;
    }

    /**
     * Never: a code does not prove a passkey; an assertion does.
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
