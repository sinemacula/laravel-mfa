<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use SineMacula\Laravel\Mfa\Support\IdentityType;

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
     * @param  string  $type
     * @param  string  $id
     */
    public function __construct(

        /** The actor's type: its morph class, or its class name. */
        public string $type,

        /** The actor's auth identifier. */
        public string $id,
    ) {}

    /**
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $identity
     * @return self
     */
    public static function of(Authenticatable $identity): self
    {
        return new self(IdentityType::of($identity), EventContext::scalarKey($identity->getAuthIdentifier()) ?? '');
    }

    /**
     * @return array{type: string, id: string}
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return ['type' => $this->type, 'id' => $this->id];
    }
}
