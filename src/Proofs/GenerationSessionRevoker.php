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
 * The default `SessionRevoker`: without an authentication layer there are no
 * sessions to end, so the identity's verification generation is advanced
 * instead (see `VerificationGeneration`), and every proof recorded under an
 * earlier one stops counting, on every device and every application at once.
 * The Laravel sessions themselves go on; the other sessions must verify again.
 *
 * Revoking every session advances the generation, and nothing else. Revoking
 * the others reads the current sign-in and its counting proofs first, advances
 * the generation, and once the change commits records those proofs again on the
 * same sign-in, stamped with exactly the generation this call advanced to, so a
 * later revocation in the same change still wins. They are recorded again only
 * while the store still names that sign-in; a refusal is dropped, which leaves
 * the current session to verify again. Advancing joins the open factor state
 * transaction, so a change that rolls back advances nothing and records nothing
 * again.
 *
 * Stateless: the store and the application are resolved on every call, and the
 * work left for the commit holds only what this call read.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class GenerationSessionRevoker implements SessionRevoker
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The container the store and the proof service are resolved from. */
        private Container $container,
    ) {}

    /**
     * Stop every proof of the identity counting, but the current sign-in's own.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     * @throws \Throwable
     */
    #[\Override]
    public function revokeOthers(MultiFactorAuthenticatable $identity): void
    {
        $store       = $this->container->make(ProofStore::class);
        $application = $this->container->make(ProofService::class)->application();
        $session     = $store->currentSession($identity, $application);
        $kept        = $session === null ? [] : $store->proofs($identity, $application);
        $generation  = VerificationGeneration::advance($identity);

        if ($kept === []) {
            return;
        }

        AfterStorageCommit::run($this->container, static function () use ($store, $identity, $application, $session, $kept, $generation): void {

            if ($store->currentSession($identity, $application) !== $session) {
                return;
            }

            try {
                foreach ($kept as $proof) {
                    $store->record($proof->withGeneration($generation));
                }
            } catch (ProofRefusedException) {
                // Fail closed: the current session verifies again.
            }
        });
    }

    /**
     * Stop every proof of the identity counting, the current sign-in's
     * included.
     *
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
}
