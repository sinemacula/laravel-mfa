<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\CodeCheck;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Secrets\RevealedSecret;

/**
 * Factor driver contract.
 *
 * Each factor type is a driver behind this one contract, registered with the
 * manager under the type's name: it states the channel kind its factors travel
 * on and the `amr` values (RFC 8176) a proof by it adds, starts an enrolment,
 * confirms a pending factor, and verifies a code. A type whose codes are
 * delivered to a destination implements `CodeDeliveryDriver` as well: the bound
 * `ChallengeGateway` then sends and checks its codes, and the driver only
 * delivers them. An application adds a type, or replaces a shipped one, by
 * registering its own driver.
 *
 * The services around a driver own the attempt counters, lockouts, events and
 * the verification record: a driver must not change them. It may change the
 * single-use material its type keeps when it is spent.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface FactorDriver
{
    /**
     * The kind of channel the type's factors travel on. The type fixes it, so
     * the combination policy never infers a channel from a type's name.
     *
     * @return \SineMacula\Laravel\Mfa\Enums\ChannelKind
     */
    public function channelKind(): ChannelKind;

    /**
     * The `amr` values (RFC 8176) a proof by the type adds on its own, such as
     * `otp` or `sms`. Values that depend on what a proof observed, such as user
     * presence, are not the driver's to claim.
     *
     * @return list<string>
     */
    public function amr(): array;

    /**
     * Start an enrolment of the pending factor, returning the secret the
     * enrolment stores encrypted on it and shows the person once (a TOTP shared
     * secret), or `null` when the type has none. The driver only returns it,
     * and stamps what the factor needs to keep on the factor.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @return ?\SineMacula\Laravel\Mfa\Secrets\RevealedSecret
     */
    public function startEnrollment(Factor $factor): ?RevealedSecret;

    /**
     * Confirm the pending factor with the first code the person submits, under
     * the binding of the enrolment: the proof that they hold what was enrolled.
     * It answers as `verify()` does, and a write it makes stays in the
     * transaction a later refusal rolls back.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  string  $code
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return \SineMacula\Laravel\Mfa\Enums\CodeCheck
     */
    public function confirm(Factor $factor, #[\SensitiveParameter] string $code, ProofBinding $binding): CodeCheck;

    /**
     * Verify the code against the factor as stored under the identity's factor
     * state lock, comparing in constant time, for the binding the verification
     * is made under: `ACCEPTED` for a code that proves the factor, `INVALID`
     * for one that does not, and `REPLAYED` only for a code that matches but
     * was already used. A write it makes stays in the transaction a later
     * refusal rolls back.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  string  $code
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return \SineMacula\Laravel\Mfa\Enums\CodeCheck
     */
    public function verify(Factor $factor, #[\SensitiveParameter] string $code, ProofBinding $binding): CodeCheck;
}
