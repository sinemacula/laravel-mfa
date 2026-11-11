<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing;

use Carbon\CarbonImmutable;
use Illuminate\Support\Str;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Testing\Contracts\VerifiedSignInRecorder;

/**
 * Default recorder: begins the sign-in and records the proofs through the proof
 * store, as a real sign-in does.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ProofStoreRecorder implements VerifiedSignInRecorder
{
    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\ProofStore  $store
     */
    public function __construct(

        /** Where the sign-in begins and the proofs go. */
        private ProofStore $store,
    ) {}

    /**
     * Refuses a store that names no current sign-in. `$at` is unused: the store
     * keeps no start time.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  \Carbon\CarbonImmutable  $at
     * @return string
     *
     * @throws \LogicException
     */
    #[\Override]
    public function begin(MultiFactorAuthenticatable $identity, string $application, CarbonImmutable $at): string // NOSONAR: the time is for another recorder
    {
        $this->store->begin($identity, $application, Str::lower((string) Str::ulid()));

        $session = $this->store->currentSession($identity, $application);

        if ($session === null) {
            throw new \LogicException(sprintf('The proof store knows of no sign-in on [%s]: a store whose begin() does nothing needs its session arranged first.', $application));
        }

        return $session;
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\ProofRefusedException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    #[\Override]
    public function record(MultiFactorAuthenticatable $identity, Proof $proof): void
    {
        $this->store->record($identity, $proof);
    }
}
