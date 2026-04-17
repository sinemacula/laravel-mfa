<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Stores;

use Carbon\Carbon;
use Carbon\CarbonInterface;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Session\Session;
use SineMacula\Laravel\Mfa\Contracts\MfaVerificationStore;
use SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException;

/**
 * Session-backed MFA verification store.
 *
 * The default `MfaVerificationStore` binding. Stores the last verification
 * timestamp keyed by the auth identifier against Laravel's session, naturally
 * scoping verification state to the current device.
 *
 * Suitable for SessionGuard, Sanctum, and any stateful auth stack. Stateless
 * stacks (JWT, Sanctum personal access tokens) should bind an alternative
 * store.
 *
 * Assumes consumers regenerate the session on auth state change (Laravel's
 * default). Apps that disable regeneration on login must also call
 * `Mfa::forgetVerification()` so a new identity cannot inherit the prior
 * identity's verification timestamp from the reused session.
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
     * Record that the given identity has just completed a successful MFA
     * verification. Stamps the session at the given time, defaulting to "now"
     * when no explicit timestamp is supplied.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $identity
     * @param  ?\Carbon\CarbonInterface  $at
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    #[\Override]
    public function markVerified(Authenticatable $identity, ?CarbonInterface $at = null): void
    {
        $timestamp = ($at ?? Carbon::now())->getTimestamp();

        $this->session->put($this->key($identity), $timestamp);
    }

    /**
     * Return the timestamp of the given identity's most recent successful MFA
     * verification, or `null` when the identity has never been verified.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $identity
     * @return ?\Carbon\CarbonInterface
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    #[\Override]
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
     * Clear any stored verification timestamp for the given identity.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $identity
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    #[\Override]
    public function forget(Authenticatable $identity): void
    {
        $this->session->forget($this->key($identity));
    }

    /**
     * Build the session key for the given identity.
     *
     * Keys by auth identifier so a session that changes owner (e.g.
     * impersonation, legacy flows that bypass session regeneration) cannot
     * inherit a prior identity's verification state. Fails loud when the auth
     * identifier is non-scalar rather than silently collapsing distinct
     * identities to a shared key.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $identity
     * @return string
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    private function key(Authenticatable $identity): string
    {
        $identifier = $identity->getAuthIdentifier();

        if (!is_string($identifier) && !is_int($identifier)) {
            $message = 'SessionMfaVerificationStore requires a string or int '
                . 'auth identifier; got ' . get_debug_type($identifier) . '.';

            throw new UnsupportedIdentifierException($message);
        }

        return self::KEY_PREFIX . $identifier;
    }
}
