<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Proofs;

use Illuminate\Contracts\Auth\Authenticatable;
use SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException;
use SineMacula\Laravel\Mfa\Support\IdentityType;

/**
 * The identity a proof binding names, by type and key; two identity types
 * sharing a key are two owners.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final readonly class ProofOwner
{
    /**
     * @param  string  $type
     * @param  string  $key
     */
    public function __construct(

        /** Morph class of an Eloquent identity, class name otherwise. */
        public string $type,

        /** The identity's key, as a string. */
        public string $key,
    ) {}

    /**
     * A key that is not a non-empty string or an integer is refused, rather
     * than collapsing identities onto one record.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $identity
     * @return self
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    public static function of(Authenticatable $identity): self
    {
        $key = $identity->getAuthIdentifier();

        if ((!is_string($key) && !is_int($key)) || $key === '') {
            throw new UnsupportedIdentifierException(sprintf('An identity\'s key must be a non-empty string or an integer to hold proofs; got [%s].', get_debug_type($key)));
        }

        return new self(IdentityType::of($identity), (string) $key);
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return self
     */
    public static function boundBy(ProofBinding $binding): self
    {
        return new self($binding->identityType, $binding->identityKey);
    }

    /**
     * Compares type and key strictly, so `'01'` and `'1'` are different owners.
     *
     * @param  self  $other
     * @return bool
     */
    public function is(self $other): bool
    {
        return $other->type === $this->type && $other->key === $this->key;
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return bool
     */
    public function owns(ProofBinding $binding): bool
    {
        return $binding->identityType === $this->type && $binding->identityKey === $this->key;
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  string  $application
     * @param  string  $session
     * @return bool
     */
    public function ownsSignIn(ProofBinding $binding, string $application, string $session): bool
    {
        return $this->owns($binding) && $binding->application === $application && $binding->sessionId === $session;
    }

    /**
     * Prefixed with the type's length, so a separator inside either part cannot
     * make two owners meet.
     *
     * @internal
     *
     * @return string
     */
    public function slot(): string
    {
        return strlen($this->type) . ':' . $this->type . '|' . $this->key;
    }
}
