<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Proofs;

use Illuminate\Contracts\Auth\Authenticatable;
use SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException;
use SineMacula\Laravel\Mfa\Support\CurrentIdentity;

/**
 * The identity a proof belongs to, as a proof's binding names it: its type (the
 * morph class of an Eloquent identity, its class name otherwise) and its key as
 * a string. Two identity types sharing a key are two owners.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ProofOwner
{
    /**
     * Constructor.
     *
     * @param  string  $type
     * @param  string  $key
     */
    public function __construct(

        /** The identity's type. */
        public string $type,

        /** The identity's key, as a string. */
        public string $key,
    ) {}

    /**
     * The owner an identity is recorded as. A key that is neither a non-empty
     * string nor an integer is refused rather than collapsing distinct
     * identities onto one record.
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

        return new self(CurrentIdentity::typeOf($identity), (string) $key);
    }

    /**
     * The owner a proof's binding names.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return self
     */
    public static function boundBy(ProofBinding $binding): self
    {
        return new self($binding->identityType, $binding->identityKey);
    }

    /**
     * Whether the binding names this owner.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return bool
     */
    public function owns(ProofBinding $binding): bool
    {
        return $binding->identityType === $this->type && $binding->identityKey === $this->key;
    }

    /**
     * The owner as one string no other owner shares: the type's length, the
     * type and the key, so a separator inside either cannot make two owners
     * meet.
     *
     * @return string
     */
    public function slot(): string
    {
        return strlen($this->type) . ':' . $this->type . '|' . $this->key;
    }
}
