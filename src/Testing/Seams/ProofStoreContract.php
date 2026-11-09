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
 * sign-in, identity or application is refused and changes nothing, the proofs
 * read for a sign-in are that current sign-in's only, a sign-in's proofs go
 * with it, a proof made before the identity's proofs are voided stops counting,
 * and forgetting a factor stops its proofs counting.
 *
 * Each assertion is given the sign-in it begins, so a store backed by real
 * sessions is tested on one the test has arranged, and the default store on
 * `SESSION`. A sign-in may already hold proofs when it is begun, such as the
 * first factor an authentication layer records on signing in, so each count is
 * taken against those. The other checks put their proofs in through a closure
 * and end the sign-in through another, so a store whose proofs and sign-ins an
 * authentication layer keeps is tested on what that layer wrote; the refusals
 * always go through `record()`. A proof of any other sign-in, identity or
 * application is refused by throwing a `ProofRefusedException`, as
 * `ProofStore::record()` declares; a store that cannot find that sign-in at all
 * refuses it the same way.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final class ProofStoreContract
{
    /** @var string The sign-in a store that keeps its own begins. */
    public const string SESSION = 'contract-sign-in';

    /** @var string A sign-in id no check begins, so never the identity's current one. */
    public const string ELSEWHERE = 'contract-sign-in-elsewhere';

    /** @var string An application no check signs the identity in to. */
    public const string ELSEWHERE_APPLICATION = 'contract-application-elsewhere';

    /** @var string The factor the additional factor proof names by default. */
    public const string FACTOR = 'contract-factor';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * A proof bound to another sign-in than the identity's current one is
     * refused by throwing, and changes nothing: the current sign-in and the
     * proof `$arrange` put in it stay as they were.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\ProofStore  $store
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $session
     * @param  ?\Closure(\SineMacula\Laravel\Mfa\Proofs\Proof): void  $arrange
     * @return void
     */
    public static function assertRefusesAProofOfAnotherSignIn(
        ProofStore $store,
        MultiFactorAuthenticatable $identity,
        string $application,
        string $session,
        ?\Closure $arrange = null,
    ): void {
        $refused = self::firstFactor($identity, $application, self::ELSEWHERE);

        self::assertRefused($store, $identity, $application, $session, $refused, $arrange, 'A proof bound to another sign-in');
    }

    /**
     * A proof of another identity's current sign-in, recorded for the identity,
     * is refused by throwing, and changes neither identity's sign-in or proofs:
     * a store must judge the identity it is handed, not the one the proof
     * names.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\ProofStore  $store
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $other
     * @param  string  $application
     * @param  string  $session
     * @param  string  $otherSession
     * @param  ?\Closure(\SineMacula\Laravel\Mfa\Proofs\Proof): void  $arrange
     * @return void
     */
    public static function assertRefusesAProofOfAnotherIdentity(
        ProofStore $store,
        MultiFactorAuthenticatable $identity,
        MultiFactorAuthenticatable $other,
        string $application,
        string $session,
        string $otherSession,
        ?\Closure $arrange = null,
    ): void {
        $store->begin($other, $application, $otherSession);

        $current = $store->currentSession($other, $application);
        $held    = $store->proofs($other, $application, $otherSession);
        $refused = self::firstFactor($other, $application, $otherSession);

        self::assertRefused($store, $identity, $application, $session, $refused, $arrange, 'A proof of another identity');

        Assert::assertSame($current, $store->currentSession($other, $application), 'A refused proof must leave the other identity\'s sign-in as it was.');
        Assert::assertEquals($held, $store->proofs($other, $application, $otherSession), 'A refused proof must not be kept for the identity it names.');
    }

    /**
     * A proof bound to another application, where the identity has no sign-in
     * of that id, is refused by throwing, and changes nothing on the sign-in
     * begun.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\ProofStore  $store
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $session
     * @param  ?\Closure(\SineMacula\Laravel\Mfa\Proofs\Proof): void  $arrange
     * @return void
     */
    public static function assertRefusesAProofOfAnotherApplication(
        ProofStore $store,
        MultiFactorAuthenticatable $identity,
        string $application,
        string $session,
        ?\Closure $arrange = null,
    ): void {
        $refused = self::firstFactor($identity, self::ELSEWHERE_APPLICATION, $session);

        self::assertRefused($store, $identity, $application, $session, $refused, $arrange, 'A proof bound to another application');
    }

    /**
     * The proofs read for a sign-in are that sign-in's only: once the sign-in
     * is replaced, reading it yields none though it held a proof, the sign-in
     * that replaced it is read on its own, and a session never begun yields
     * none.
     *
     * The proofs are put in by `$arrange`, and the sign-in replaced by
     * `$replace`, which returns the new sign-in's id: by default the store's
     * own `record()` and `begin()`, and for a store whose proofs and sign-ins
     * another layer keeps, that layer's.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\ProofStore  $store
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $session
     * @param  ?\Closure(): string  $replace
     * @param  ?\Closure(\SineMacula\Laravel\Mfa\Proofs\Proof): void  $arrange
     * @return void
     */
    public static function assertReadsOnlyTheNamedSignIn(
        ProofStore $store,
        MultiFactorAuthenticatable $identity,
        string $application,
        string $session,
        ?\Closure $replace = null,
        ?\Closure $arrange = null,
    ): void {
        $arrange ??= static fn (Proof $proof) => $store->record($identity, $proof);
        $replace ??= static function () use ($store, $identity, $application, $session): string {
            $store->begin($identity, $application, 'replaced-' . $session);

            return 'replaced-' . $session;
        };

        $store->begin($identity, $application, $session);

        $held = count($store->proofs($identity, $application, $session));

        $arrange(self::firstFactor($identity, $application, $session));

        Assert::assertCount($held + 1, $store->proofs($identity, $application, $session), 'A proof of the current sign-in must be read for it.');
        Assert::assertSame([], $store->proofs($identity, $application, self::ELSEWHERE), 'A session never begun must yield no proof.');

        $replacement = $replace();

        Assert::assertNotSame($session, $replacement, 'Replacing the sign-in must begin another.');
        Assert::assertSame($replacement, $store->currentSession($identity, $application), 'The sign-in that replaced it must be the current one.');
        Assert::assertSame([], $store->proofs($identity, $application, $session), 'A sign-in since replaced must yield no proof, though it held one.');

        $replacing = count($store->proofs($identity, $application, $replacement));

        $arrange(self::firstFactor($identity, $application, $replacement));

        Assert::assertCount($replacing + 1, $store->proofs($identity, $application, $replacement), 'A proof of the sign-in that replaced it must be read for it.');
    }

    /**
     * A proof of the current sign-in is kept, and goes when the sign-in is
     * ended.
     *
     * The proof is put in by `$arrange`, and the sign-in ended by `$end`: by
     * default the store's own `record()` and `forget()`, and for a store whose
     * proofs and sign-ins another layer keeps, that layer's.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\ProofStore  $store
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $session
     * @param  ?\Closure(\SineMacula\Laravel\Mfa\Proofs\Proof): void  $arrange
     * @param  ?\Closure(): void  $end
     * @return void
     */
    public static function assertForgettingASignInForgetsItsProofs(
        ProofStore $store,
        MultiFactorAuthenticatable $identity,
        string $application,
        string $session,
        ?\Closure $arrange = null,
        ?\Closure $end = null,
    ): void {
        $arrange ??= static fn (Proof $proof) => $store->record($identity, $proof);
        $end     ??= static fn () => $store->forget($identity, $application);

        $store->begin($identity, $application, $session);

        $held = count($store->proofs($identity, $application, $session));

        $arrange(self::firstFactor($identity, $application, $session));

        Assert::assertSame($session, $store->currentSession($identity, $application), 'The sign-in begun must be the current one.');
        Assert::assertCount($held + 1, $store->proofs($identity, $application, $session), 'A proof of the current sign-in must be kept.');

        $end();

        Assert::assertNull($store->currentSession($identity, $application), 'A forgotten sign-in must not be current.');
        Assert::assertSame([], $store->proofs($identity, $application, $session), 'A forgotten sign-in must keep no proof.');
    }

    /**
     * Voiding the identity's proofs stops every proof made before counting.
     *
     * The void is the store's own: advancing the identity's verification
     * generation for a store that keeps it, as `voidByGeneration()` does, or
     * what the bound `SessionRevoker` does on a reset for a store backed by an
     * authentication layer's sessions.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\ProofStore  $store
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $session
     * @param  \Closure(\SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable): void  $void
     * @param  ?\Closure(\SineMacula\Laravel\Mfa\Proofs\Proof): void  $arrange
     * @return void
     */
    public static function assertVoidedProofsStopCounting(
        ProofStore $store,
        MultiFactorAuthenticatable $identity,
        string $application,
        string $session,
        \Closure $void,
        ?\Closure $arrange = null,
    ): void {
        $arrange ??= static fn (Proof $proof) => $store->record($identity, $proof);

        $store->begin($identity, $application, $session);

        $held = count($store->proofs($identity, $application, $session));

        $arrange(self::firstFactor($identity, $application, $session));

        Assert::assertCount($held + 1, $store->proofs($identity, $application, $session), 'A proof of the current sign-in must count before the proofs are voided.');

        $void($identity);

        Assert::assertSame([], $store->proofs($identity, $application, $session), 'A proof made before the identity\'s proofs were voided must stop counting.');
    }

    /**
     * Void the identity's proofs by advancing its verification generation, as a
     * store that keeps the generation honours.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return void
     *
     * @throws \Throwable
     */
    public static function voidByGeneration(MultiFactorAuthenticatable $identity): void
    {
        VerificationGeneration::advance($identity);
    }

    /**
     * Forgetting a factor stops the proofs made with it counting, and leaves
     * the others.
     *
     * The further proof names `$factor`: by default `FACTOR`, and for a store
     * that counts a proof only while the identity holds its factor, one the
     * test enrolled.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\ProofStore  $store
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $session
     * @param  string  $factor
     * @param  ?\Closure(\SineMacula\Laravel\Mfa\Proofs\Proof): void  $arrange
     * @return void
     */
    public static function assertForgettingAFactorStopsItsProofsCounting(
        ProofStore $store,
        MultiFactorAuthenticatable $identity,
        string $application,
        string $session,
        string $factor = self::FACTOR,
        ?\Closure $arrange = null,
    ): void {
        $arrange ??= static fn (Proof $proof) => $store->record($identity, $proof);

        $store->begin($identity, $application, $session);

        $held = self::kinds($store->proofs($identity, $application, $session));

        $arrange(self::firstFactor($identity, $application, $session));
        $arrange(self::additionalFactor($identity, $application, $session, $factor));

        $arranged = self::kinds($store->proofs($identity, $application, $session));

        Assert::assertSame([...$held, ProofKind::FIRST_FACTOR, ProofKind::ADDITIONAL_FACTOR], $arranged, 'Both proofs must count before the factor is forgotten.');

        $store->forgetFactor($identity, $factor);

        $kinds = self::kinds($store->proofs($identity, $application, $session));

        Assert::assertSame([...$held, ProofKind::FIRST_FACTOR], $kinds, 'Only the proofs made with the forgotten factor must stop counting.');
    }

    /**
     * The proof is refused by throwing a `ProofRefusedException`, and the
     * sign-in begun, holding a proof `$arrange` put in it, stays current and
     * holds what it did.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\ProofStore  $store
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $session
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $refused
     * @param  ?\Closure(\SineMacula\Laravel\Mfa\Proofs\Proof): void  $arrange
     * @param  string  $what
     * @return void
     */
    private static function assertRefused(
        ProofStore $store,
        MultiFactorAuthenticatable $identity,
        string $application,
        string $session,
        Proof $refused,
        ?\Closure $arrange,
        string $what,
    ): void {
        $arrange ??= static fn (Proof $proof) => $store->record($identity, $proof);

        $store->begin($identity, $application, $session);

        $held = count($store->proofs($identity, $application, $session));

        $arrange(self::firstFactor($identity, $application, $session));

        $kept = $store->proofs($identity, $application, $session);

        Assert::assertCount($held + 1, $kept, 'A proof of the current sign-in must be kept before the refusal.');

        try {
            $store->record($identity, $refused);
        } catch (ProofRefusedException) {
            Assert::assertSame($session, $store->currentSession($identity, $application), 'A refused proof must leave the sign-in current.');
            Assert::assertEquals($kept, $store->proofs($identity, $application, $session), 'A refused proof must change nothing.');

            return;
        }

        Assert::fail($what . ' must be refused by throwing a ProofRefusedException.');
    }

    /**
     * The kind of each proof, in order.
     *
     * @param  list<\SineMacula\Laravel\Mfa\Proofs\Proof>  $proofs
     * @return list<\SineMacula\Laravel\Mfa\Enums\ProofKind>
     */
    private static function kinds(array $proofs): array
    {
        return array_map(static fn (Proof $proof): ProofKind => $proof->kind, $proofs);
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
     * An authenticator app proof of the identity's factor, bound to the
     * sign-in.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $session
     * @param  string  $factor
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     */
    private static function additionalFactor(MultiFactorAuthenticatable $identity, string $application, string $session, string $factor): Proof
    {
        return self::proof($identity, ProofKind::ADDITIONAL_FACTOR, 'totp', new Channel(ChannelKind::AUTHENTICATOR_APP, $factor), $factor, $application, $session);
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
    private static function proof(
        MultiFactorAuthenticatable $identity,
        ProofKind $kind,
        string $method,
        Channel $channel,
        ?string $reference,
        string $application,
        string $session,
    ): Proof {
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
