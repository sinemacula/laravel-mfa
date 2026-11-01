<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use SineMacula\Laravel\Mfa\Enums\ChannelKind;

/**
 * Factor driver contract.
 *
 * Each factor type is a driver behind this one contract, registered with the
 * manager under the type's name: it states the channel kind its factors travel
 * on and the `amr` values (RFC 8176) a proof by it adds, starts an enrolment,
 * confirms a pending factor, issues a challenge, and verifies a code. A type
 * whose codes are delivered to a destination implements `CodeDeliveryDriver` as
 * well: the package then sends and checks its codes itself, and the driver only
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
     * Start an enrolment of the pending factor, returning the secret the caller
     * stores on it and shows the person once (a TOTP shared secret), or `null`
     * when the type has none.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @return ?string
     */
    public function startEnrollment(Factor $factor): ?string;

    /**
     * Confirm the pending factor with the first code the person submits: the
     * proof that they hold what was enrolled.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  string  $code
     * @return bool
     *
     * @imperative
     */
    public function confirm(Factor $factor, #[\SensitiveParameter] string $code): bool;

    /**
     * Issue a challenge for the factor: nothing for a type whose codes are made
     * where they are held (TOTP). A type whose codes are delivered has them
     * sent through `CodeDeliveryDriver::deliver()` instead.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @return void
     */
    public function issueChallenge(Factor $factor): void;

    /**
     * Verify the code against the factor, comparing in constant time.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  string  $code
     * @return bool
     */
    public function verify(Factor $factor, #[\SensitiveParameter] string $code): bool;
}
