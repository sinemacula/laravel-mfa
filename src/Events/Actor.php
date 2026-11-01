<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use SineMacula\Laravel\Mfa\Support\CurrentIdentity;

/**
 * Who took an action on someone else's factors, such as a reset or a lifted
 * lockout, by type and id only: never the model, so an event carrying it
 * serialises safely.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Actor implements \JsonSerializable
{
    /**
     * Constructor.
     *
     * @param  string  $type
     * @param  string  $id
     */
    public function __construct(

        /** The actor's type: its morph class, or its class name. */
        public string $type,

        /** The actor's identifier. */
        public string $id,
    ) {}

    /**
     * The actor an identity is, recorded by its morph class (or class name) and
     * its auth identifier.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $identity
     * @return self
     */
    public static function of(Authenticatable $identity): self
    {
        return new self(CurrentIdentity::typeOf($identity), EventContext::scalarKey($identity->getAuthIdentifier()) ?? '');
    }

    /**
     * Render the actor as its type and id.
     *
     * @return array{type: string, id: string}
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return ['type' => $this->type, 'id' => $this->id];
    }
}
