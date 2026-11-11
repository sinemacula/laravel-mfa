<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Applications;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Mfa\Assurance\Channel;
use SineMacula\Laravel\Mfa\Assurance\ObservedProperties;
use SineMacula\Laravel\Mfa\Contracts\FirstFactorResolver;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;

/**
 * The default `FirstFactorResolver`, reading the application's declared
 * `first_factor`. The proof is dated at the Unix epoch, so it establishes a
 * channel but never satisfies a maximum age.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class DeclaredFirstFactorResolver implements FirstFactorResolver
{
    /**
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** Resolves the configuration and the store per call. */
        private Container $container,
    ) {}

    /**
     * Null without a declaration or a sign-in the proof store knows.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return ?\SineMacula\Laravel\Mfa\Proofs\Proof
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    #[\Override]
    public function resolve(MultiFactorAuthenticatable $identity, string $application): ?Proof
    {
        $declared = (new ApplicationSettings($this->container->make(Repository::class), $application))->firstFactor();

        if ($declared === null) {
            return null;
        }

        $session = $this->container->make(ProofStore::class)->currentSession($identity, $application);

        if ($session === null) {
            return null;
        }

        $owner = ProofOwner::of($identity);

        return new Proof(
            kind      : ProofKind::FIRST_FACTOR,
            method    : $declared->method,
            channel   : new Channel($declared->channel),
            reference : null,
            properties: ObservedProperties::none(),
            provedAt  : CarbonImmutable::createFromTimestamp(0),
            binding   : new ProofBinding($owner->type, $owner->key, $application, $session, Purpose::SIGN_IN),
            generation: VerificationGeneration::current($identity),
        );
    }
}
