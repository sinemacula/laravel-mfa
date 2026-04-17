<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use Carbon\CarbonInterface;
use Illuminate\Contracts\Auth\Authenticatable;

/**
 * MFA verification store contract.
 *
 * Persists the "last successfully verified" timestamp for an
 * authenticatable identity so the MFA manager can decide whether
 * an existing verification has expired. Bind a custom implementation
 * to scope verification differently (per-device, per-IP, etc.); the
 * shipped default keys by session.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
interface MfaVerificationStore
{
    /**
     * Record that the given identity has just completed a successful MFA
     * verification. Stores implementations use the supplied timestamp when
     * provided, falling back to "now" otherwise. Passing an explicit `$at`
     * lets paired-mode stores (e.g. a device-backed implementation) stamp
     * the persistence layer atomically with the verification event.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $identity
     * @param  ?\Carbon\CarbonInterface  $at
     * @return void
     */
    public function markVerified(Authenticatable $identity, ?CarbonInterface $at = null): void;

    /**
     * Return the timestamp of the given identity's most recent
     * successful MFA verification, or `null` when the identity has
     * never been verified (or the previous verification has been
     * explicitly forgotten).
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $identity
     * @return ?\Carbon\CarbonInterface
     */
    public function lastVerifiedAt(Authenticatable $identity): ?CarbonInterface;

    /**
     * Clear any stored verification timestamp for the given
     * identity. Called on logout and on administrative reset
     * flows.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $identity
     * @return void
     */
    public function forget(Authenticatable $identity): void;
}
