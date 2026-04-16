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
 * an existing verification has expired.
 *
 * Ships with `SessionMfaVerificationStore` as the default — keys
 * the timestamp by identifier against Laravel's session store, so
 * verification is scoped to the current session / device on the
 * standalone stateless adoption path.
 *
 * Consumers running a stateless stack (JWT, Sanctum personal
 * access tokens) bind an alternative implementation. In paired
 * mode with `sinemacula/laravel-authentication`, the expected glue
 * is a `DeviceMfaVerificationStore` that reads/writes
 * `last_mfa_verified_at` on the authenticated device record —
 * delivered by the parent `laravel-iam` package rather than this
 * package directly, to keep the zero-dependency guarantee intact.
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
