<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\CodeCheck;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Secrets\RevealedSecret;

/**
 * A factor type, registered under its name; it never touches attempt counters,
 * lockouts, events or the verification record.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface FactorDriver
{
    /**
     * Fixed by the type, so the combination policy never infers a channel from
     * a name.
     *
     * @return \SineMacula\Laravel\Mfa\Enums\ChannelKind
     */
    public function channelKind(): ChannelKind;

    /**
     * The `amr` values (RFC 8176) the type adds on its own; values that depend
     * on what a proof observed are not the driver's to claim.
     *
     * @return list<string>
     */
    public function amr(): array;

    /**
     * The secret shown once and stored encrypted (a TOTP shared secret), or
     * `null` when the type has none.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @return ?\SineMacula\Laravel\Mfa\Secrets\RevealedSecret
     */
    public function startEnrollment(Factor $factor): ?RevealedSecret;

    /**
     * Confirm the pending factor with the first code submitted, answering as
     * `verify()` does.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  string  $code
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return \SineMacula\Laravel\Mfa\Enums\CodeCheck
     */
    public function confirm(Factor $factor, #[\SensitiveParameter] string $code, ProofBinding $binding): CodeCheck;

    /**
     * Compare in constant time against the factor as stored under the lock;
     * `REPLAYED` only for a matching code already used.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  string  $code
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return \SineMacula\Laravel\Mfa\Enums\CodeCheck
     */
    public function verify(Factor $factor, #[\SensitiveParameter] string $code, ProofBinding $binding): CodeCheck;
}
