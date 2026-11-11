<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Seams;

use SineMacula\Laravel\Mfa\Contracts\EventContextResolver;
use SineMacula\Laravel\Mfa\Events\EventSubject;

/**
 * Puts an object in the context only with an identity or only without one, so
 * the contract kit must ask both ways to reject it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ObjectContextResolver implements EventContextResolver
{
    /**
     * @param  bool  $forIdentity
     */
    public function __construct(

        /** Whether the object is put in with an identity or without one. */
        private bool $forIdentity,
    ) {}

    /**
     * @param  \SineMacula\Laravel\Mfa\Events\EventSubject  $subject
     * @return array<string, int|string|null>
     */
    #[\Override]
    public function resolve(EventSubject $subject): array
    {
        $identity = $subject->identity;
        $client   = $subject->client;

        // The object breaks the contract on purpose.
        if ($this->forIdentity) {
            // @phpstan-ignore return.type
            return $identity === null ? ['identity_id' => null] : ['identity_id' => 'person-1', 'client' => $client];
        }

        // @phpstan-ignore return.type
        return $identity === null ? ['identity_id' => null, 'at' => new \DateTimeImmutable] : ['identity_id' => 'person-1'];
    }
}
