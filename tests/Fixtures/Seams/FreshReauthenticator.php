<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Seams;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Assurance\Channel;
use SineMacula\Laravel\Mfa\Assurance\ObservedProperties;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Contracts\Reauthenticator;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;

/**
 * A reauthenticator that proves the password again, the given number of
 * seconds ago, on the identity's current sign-in, and counts how often it is
 * asked.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class FreshReauthenticator implements Reauthenticator
{
    /** @var int How often the reauthenticator has been asked. */
    public int $asked = 0;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\ProofStore  $store
     * @param  int  $secondsAgo
     * @param  ?string  $session
     */
    public function __construct(

        /** The store the identity's current sign-in is read from. */
        private readonly ProofStore $store,

        /** How long ago the reauthentication was made. */
        private readonly int $secondsAgo = 0,

        /** The session the proof is bound to, or `null` for the current sign-in. */
        private readonly ?string $session = null,
    ) {}

    /**
     * A reauthentication with the password on the identity's sign-in, or none
     * without one.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return ?\SineMacula\Laravel\Mfa\Proofs\Proof
     */
    #[\Override]
    public function reauthenticate(MultiFactorAuthenticatable $identity, string $application): ?Proof
    {
        $this->asked++;

        $session = $this->session ?? $this->store->currentSession($identity, $application);

        if ($session === null) {
            return null;
        }

        $owner = ProofOwner::of($identity);

        return new Proof(
            kind      : ProofKind::FIRST_FACTOR_REAUTHENTICATION,
            method    : 'password',
            channel   : new Channel(ChannelKind::PASSWORD),
            reference : null,
            properties: ObservedProperties::none(),
            provedAt  : CarbonImmutable::now()->subSeconds($this->secondsAgo),
            binding   : new ProofBinding($owner->type, $owner->key, $application, $session, Purpose::REAUTHENTICATE),
            generation: VerificationGeneration::current($identity),
        );
    }
}
