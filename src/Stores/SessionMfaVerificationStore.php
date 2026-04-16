<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Stores;

use Carbon\Carbon;
use Carbon\CarbonInterface;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Session\Session;
use SineMacula\Laravel\Mfa\Contracts\MfaVerificationStore;

/**
 * Session-backed MFA verification store.
 *
 * The default `MfaVerificationStore` binding. Stores the last
 * verification timestamp keyed by the authenticatable's auth
 * identifier against Laravel's session store. Verification state is
 * naturally scoped to the current session (and therefore the
 * current device) because sessions are per-device by construction.
 *
 * Suitable for SessionGuard, Sanctum, and any other stateful auth
 * stack. Stateless stacks (JWT, Sanctum personal access tokens)
 * should bind an alternative store — see the class-level docblock
 * on `MfaVerificationStore`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
final readonly class SessionMfaVerificationStore implements MfaVerificationStore
{
    /** @var string Prefix applied to every key written by this store. */
    private const string KEY_PREFIX = 'mfa.verified_at.';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Session\Session  $session
     */
    public function __construct(

        /** Session store used to persist verification timestamps. */
        private Session $session,

    ) {}

    /**
     * Record that the given identity has just completed a
     * successful MFA verification.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $identity
     * @return void
     */
    public function markVerified(Authenticatable $identity): void
    {
        $this->session->put($this->key($identity), Carbon::now()->getTimestamp());
    }

    /**
     * Return the timestamp of the given identity's most recent
     * successful MFA verification, or `null` when the identity has
     * never been verified.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $identity
     * @return ?\Carbon\CarbonInterface
     */
    public function lastVerifiedAt(Authenticatable $identity): ?CarbonInterface
    {
        /** @var mixed $timestamp */
        $timestamp = $this->session->get($this->key($identity));

        if (!is_int($timestamp)) {
            return null;
        }

        return Carbon::createFromTimestamp($timestamp);
    }

    /**
     * Clear any stored verification timestamp for the given
     * identity.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $identity
     * @return void
     */
    public function forget(Authenticatable $identity): void
    {
        $this->session->forget($this->key($identity));
    }

    /**
     * Build the session key for the given identity.
     *
     * Keys by auth identifier so a session that changes owner
     * (e.g. impersonation, legacy flows that bypass session
     * regeneration) cannot inherit a prior identity's verification
     * state.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $identity
     * @return string
     */
    private function key(Authenticatable $identity): string
    {
        $identifier = $identity->getAuthIdentifier();

        $suffix = is_string($identifier) || is_int($identifier) ? (string) $identifier : '_';

        return self::KEY_PREFIX . $suffix;
    }
}
