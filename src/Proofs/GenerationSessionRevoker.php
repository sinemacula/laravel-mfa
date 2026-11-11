<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Proofs;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Contracts\SessionRevoker;
use SineMacula\Laravel\Mfa\Database\AfterStorageCommit;
use SineMacula\Laravel\Mfa\Exceptions\ProofRefusedException;

/**
 * The default `SessionRevoker`: with no sessions of its own to end, it advances
 * the verification generation so every earlier proof stops counting.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class GenerationSessionRevoker implements SessionRevoker
{
    /**
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** Resolves the store on every call. */
        private Container $container,
    ) {}

    /**
     * Keep the current sign-in's other proofs by recording them again under the
     * new generation once the change commits.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $factorId
     * @param  string  $application
     * @param  string  $session
     * @return \SineMacula\Laravel\Mfa\Proofs\RemovalRevocation
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     * @throws \Throwable
     */
    #[\Override]
    public function factorRemoved(MultiFactorAuthenticatable $identity, string $factorId, string $application, string $session): RemovalRevocation
    {
        $store      = $this->container->make(ProofStore::class);
        $current    = $store->currentSession($identity, $application) === $session;
        $kept       = $current ? self::without($factorId, $store->proofs($identity, $application, $session)) : [];
        $generation = VerificationGeneration::advance($identity);

        if ($kept !== []) {
            $this->recordAgainOnCommit($identity, $application, $session, $kept, $generation);
        }

        return RemovalRevocation::othersEnded();
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return void
     *
     * @throws \Throwable
     */
    #[\Override]
    public function revokeAll(MultiFactorAuthenticatable $identity): void
    {
        VerificationGeneration::advance($identity);
    }

    /**
     * Only while the store still names the sign-in, so a later revocation in
     * the same change still wins.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $session
     * @param  array<int, \SineMacula\Laravel\Mfa\Proofs\Proof>  $kept
     * @param  int  $generation
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Throwable
     */
    private function recordAgainOnCommit(MultiFactorAuthenticatable $identity, string $application, string $session, array $kept, int $generation): void
    {
        $store = $this->container->make(ProofStore::class);

        AfterStorageCommit::run($this->container, static function () use ($store, $identity, $application, $session, $kept, $generation): void {

            if ($store->currentSession($identity, $application) !== $session) {
                return;
            }

            try {
                foreach ($kept as $proof) {
                    $store->record($identity, $proof->withGeneration($generation));
                }
            } catch (ProofRefusedException) {
                // The current session verifies again.
            }
        });
    }

    /**
     * @param  string  $factorId
     * @param  list<\SineMacula\Laravel\Mfa\Proofs\Proof>  $proofs
     * @return array<int, \SineMacula\Laravel\Mfa\Proofs\Proof>
     */
    private static function without(string $factorId, array $proofs): array
    {
        return array_filter($proofs, static fn (Proof $proof): bool => $proof->reference !== $factorId);
    }
}
