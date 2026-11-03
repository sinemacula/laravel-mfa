<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Seams;

use Illuminate\Http\Request;
use SineMacula\Laravel\Mfa\Contracts\EventContextResolver;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;

/**
 * An event context resolver that puts an object in the context in one case
 * only: when given an identity and a request, or when given neither. In the
 * other case its context is scalar, so the contract kit must ask it both ways
 * to reject it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ObjectContextResolver implements EventContextResolver
{
    /**
     * Constructor.
     *
     * @param  bool  $forIdentity
     */
    public function __construct(

        /** Whether the object is put in for an identity, rather than for none. */
        private bool $forIdentity,
    ) {}

    /**
     * The context, holding the request when given one and told to, or the time
     * when given no identity and told to.
     *
     * @param  ?\SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  ?\Illuminate\Http\Request  $request
     * @return array<string, int|string|null>
     */
    #[\Override]
    public function resolve(?MultiFactorAuthenticatable $identity, ?Request $request): array
    {
        // The object breaks the contract on purpose, for the kit to reject.
        if ($this->forIdentity) {
            // @phpstan-ignore return.type
            return $identity === null ? ['identity_id' => null] : ['identity_id' => 'person-1', 'request' => $request];
        }

        // @phpstan-ignore return.type
        return $identity === null ? ['identity_id' => null, 'at' => new \DateTimeImmutable] : ['identity_id' => 'person-1'];
    }
}
