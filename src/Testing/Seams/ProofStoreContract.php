<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Mfa\Assurance\Channel;
use SineMacula\Laravel\Mfa\Assurance\ObservedProperties;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Exceptions\ProofRefusedException;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;

/**
 * What every `ProofStore` must guarantee, as assertions: a proof of another
 * sign-in is refused, a sign-in's proofs go with it, a proof made under an
 * earlier verification generation stops counting, and forgetting a factor
 * stops its proofs counting.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final class ProofStoreContract
{
    /** @var string The sign-in each assertion begins. */
    public const string SESSION = 'contract-sign-in';

    /** @var string The factor the additional factor proof names. */
    public const string FACTOR = 'contract-factor';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * A proof bound to another sign-in than the identity's current one is
     * refused by throwing, and not kept.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\ProofStore  $store
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return void
     */
    public static function assertRefusesAProofOfAnotherSignIn(ProofStore $store, MultiFactorAuthenticatable $identity, string $application): void
    {
        $store->begin($identity, $application, self::SESSION);

        try {
            $store->record(self::firstFactor($identity, $application, 'another-sign-in'));
        } catch (ProofRefusedException) {
            Assert::assertSame([], $store->proofs($identity, $application), 'A refused proof must not be kept.');

            return;
        }

        Assert::fail('A proof bound to another sign-in must be refused by throwing a ProofRefusedException.');
    }

    /**
     * A proof of the current sign-in is kept, and goes when the sign-in is
     * forgotten.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\ProofStore  $store
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return void
     */
    public static function assertForgettingASignInForgetsItsProofs(ProofStore $store, MultiFactorAuthenticatable $identity, string $application): void
    {
        $store->begin($identity, $application, self::SESSION);
        $store->record(self::firstFactor($identity, $application, self::SESSION));

        Assert::assertSame(self::SESSION, $store->currentSession($identity, $application), 'The sign-in begun must be the current one.');
        Assert::assertCount(1, $store->proofs($identity, $application), 'A proof of the current sign-in must be kept.');

        $store->forget($identity, $application);

        Assert::assertNull($store->currentSession($identity, $application), 'A forgotten sign-in must not be current.');
        Assert::assertSame([], $store->proofs($identity, $application), 'A forgotten sign-in must keep no proof.');
    }

    /**
     * Advancing the identity's verification generation stops every proof made
     * under an earlier one counting.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\ProofStore  $store
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return void
     *
     * @throws \Throwable
     */
    public static function assertAnEarlierGenerationStopsCounting(ProofStore $store, MultiFactorAuthenticatable $identity, string $application): void
    {
        $store->begin($identity, $application, self::SESSION);
        $store->record(self::firstFactor($identity, $application, self::SESSION));

        VerificationGeneration::advance($identity);

        Assert::assertSame([], $store->proofs($identity, $application), 'A proof made under an earlier verification generation must stop counting.');
    }

    /**
     * Forgetting a factor stops the proofs made with it counting, and leaves
     * the others.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\ProofStore  $store
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return void
     */
    public static function assertForgettingAFactorStopsItsProofsCounting(ProofStore $store, MultiFactorAuthenticatable $identity, string $application): void
    {
        $store->begin($identity, $application, self::SESSION);
        $store->record(self::firstFactor($identity, $application, self::SESSION));
        $store->record(self::additionalFactor($identity, $application));

        $store->forgetFactor($identity, self::FACTOR);

        $kinds = array_map(static fn (Proof $proof): ProofKind => $proof->kind, $store->proofs($identity, $application));

        Assert::assertSame([ProofKind::FIRST_FACTOR], $kinds, 'Only the proofs made with the forgotten factor must stop counting.');
    }

    /**
     * A password first factor of the identity, bound to the sign-in.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $session
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     */
    private static function firstFactor(MultiFactorAuthenticatable $identity, string $application, string $session): Proof
    {
        return self::proof($identity, ProofKind::FIRST_FACTOR, 'password', new Channel(ChannelKind::PASSWORD), null, $application, $session);
    }

    /**
     * An authenticator app proof of the identity's contract factor, bound to
     * the contract's sign-in.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     */
    private static function additionalFactor(MultiFactorAuthenticatable $identity, string $application): Proof
    {
        return self::proof($identity, ProofKind::ADDITIONAL_FACTOR, 'totp', new Channel(ChannelKind::AUTHENTICATOR_APP, self::FACTOR), self::FACTOR, $application, self::SESSION);
    }

    /**
     * A proof of the identity made now, under its current verification
     * generation.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Enums\ProofKind  $kind
     * @param  string  $method
     * @param  \SineMacula\Laravel\Mfa\Assurance\Channel  $channel
     * @param  ?string  $reference
     * @param  string  $application
     * @param  string  $session
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     */
    private static function proof(MultiFactorAuthenticatable $identity, ProofKind $kind, string $method, Channel $channel, ?string $reference, string $application, string $session): Proof
    {
        $owner = ProofOwner::of($identity);

        return new Proof(
            kind      : $kind,
            method    : $method,
            channel   : $channel,
            reference : $reference,
            properties: ObservedProperties::none(),
            provedAt  : CarbonImmutable::now(),
            binding   : new ProofBinding($owner->type, $owner->key, $application, $session, Purpose::SIGN_IN),
            generation: VerificationGeneration::current($identity),
        );
    }
}
