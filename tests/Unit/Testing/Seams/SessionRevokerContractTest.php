<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing\Seams;

use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Contracts\SessionRevoker;
use SineMacula\Laravel\Mfa\Database\StorageConnection;
use SineMacula\Laravel\Mfa\Proofs\GenerationSessionRevoker;
use SineMacula\Laravel\Mfa\Proofs\SessionProofStore;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;
use SineMacula\Laravel\Mfa\Testing\Seams\Concerns\SessionRevokerTests;
use SineMacula\Laravel\Mfa\Testing\Seams\SessionRevokerContract;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Requirements\SignInProofs;
use Tests\Fixtures\Seams\FaultySeams;
use Tests\Fixtures\Seams\ForgettingSessionRevoker;
use Tests\TestCase;

/**
 * The `SessionRevoker` contract kit proves the default, which advances the
 * identity's verification generation, and rejects a revoker that revokes
 * nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionRevokerContract::class)]
#[CoversClass(GenerationSessionRevoker::class)]
final class SessionRevokerContractTest extends TestCase
{
    use SessionRevokerTests;

    /** @var string The id of the factor the kit's removals name. */
    private const string REMOVED_FACTOR = 'removed-factor';

    /** @var \SineMacula\Laravel\Mfa\Proofs\SessionProofStore The store of the identity's other device. */
    private SessionProofStore $otherDevice;

    /**
     * Give the identity another device.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->otherDevice = new SessionProofStore(new Store('other-device', new ArraySessionHandler(10)));
    }

    /**
     * The kit rejects a revoker that revokes nothing.
     *
     * @return void
     */
    public function testRejectsARevokerThatRevokesNothing(): void
    {
        $this->expectException(AssertionFailedError::class);

        SessionRevokerContract::assertRemovingAFactorStopsAnotherSessionCounting(
            new FaultySeams,
            $this->revokedIdentity(),
            self::REMOVED_FACTOR,
            SignInProofs::SESSION,
            $this->verifyAnotherSession(...),
            $this->doesAnotherSessionCount(...),
        );
    }

    /**
     * The kit rejects a revoker that revokes nothing when revoking every
     * session.
     *
     * @return void
     */
    public function testRejectsARevokerThatRevokesNothingOfAll(): void
    {
        $this->expectException(AssertionFailedError::class);

        SessionRevokerContract::assertRevokingAllStopsAnotherSessionCounting(
            new FaultySeams,
            $this->revokedIdentity(),
            $this->verifyAnotherSession(...),
            $this->doesAnotherSessionCount(...),
        );
    }

    /**
     * The kit rejects a revoker that ends the other session outside the
     * caller's transaction, so a rollback leaves it ended.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRejectsARevokerThatIgnoresARollback(): void
    {
        $this->expectException(AssertionFailedError::class);

        SessionRevokerContract::assertARolledBackRevocationLeavesSessionsCounting(
            new ForgettingSessionRevoker($this->otherDevice, SignInProofs::APPLICATION),
            $this->revokedIdentity(),
            $this->verifyAnotherSession(...),
            $this->doesAnotherSessionCount(...),
            self::REMOVED_FACTOR,
            SignInProofs::SESSION,
        );
    }

    /**
     * The kit rejects a revoker that spares the current session when told a
     * factor was removed from another sign-in.
     *
     * @return void
     */
    public function testRejectsARevokerThatSparesTheCurrentSessionForAnotherSignIn(): void
    {
        $identity = $this->revokedIdentity();

        $this->currentSessionOf($identity);

        $this->expectException(AssertionFailedError::class);

        SessionRevokerContract::assertRemovingAFactorFromAnotherSignInSparesNothing(
            new FaultySeams,
            $identity,
            self::REMOVED_FACTOR,
            'another-sign-in',
            $this->doesCurrentSessionCount(...),
        );
    }

    /**
     * The kit rejects a contract whose current session never counted, rather
     * than passing a removal from another sign-in.
     *
     * @return void
     */
    public function testRejectsACurrentSessionThatNeverCounted(): void
    {
        $this->expectException(AssertionFailedError::class);

        SessionRevokerContract::assertRemovingAFactorFromAnotherSignInSparesNothing(
            $this->sessionRevoker(),
            $this->revokedIdentity(),
            self::REMOVED_FACTOR,
            'another-sign-in',
            $this->doesCurrentSessionCount(...),
        );
    }

    /**
     * The kit passes a revoker that refuses a sign-in that is not the
     * identity's current one by throwing.
     *
     * @return void
     */
    public function testPassesARevokerThatRefusesAnotherSignInByThrowing(): void
    {
        $identity = $this->revokedIdentity();

        $this->currentSessionOf($identity);

        SessionRevokerContract::assertRemovingAFactorFromAnotherSignInSparesNothing(
            new ForgettingSessionRevoker($this->otherDevice, SignInProofs::APPLICATION, new \LogicException('Not the identity\'s session.')),
            $identity,
            self::REMOVED_FACTOR,
            'another-sign-in',
            $this->doesCurrentSessionCount(...),
        );

        self::assertTrue($this->doesCurrentSessionCount($identity));
    }

    /**
     * A revoker that fails leaves the kit's change rolled back, and its failure
     * propagates.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailingRevocationIsRolledBack(): void
    {
        $connection = DB::connection(StorageConnection::name());
        $level      = $connection->transactionLevel();
        $failure    = new \LogicException('The revoker failed.');

        try {
            SessionRevokerContract::assertARolledBackRevocationLeavesSessionsCounting(
                new ForgettingSessionRevoker($this->otherDevice, SignInProofs::APPLICATION, $failure),
                $this->revokedIdentity(),
                $this->verifyAnotherSession(...),
                $this->doesAnotherSessionCount(...),
                self::REMOVED_FACTOR,
                SignInProofs::SESSION,
            );
            self::fail('The revoker\'s failure was expected to propagate.');
        } catch (\LogicException $exception) {
            self::assertSame($failure, $exception);
        }

        self::assertSame($level, $connection->transactionLevel());
    }

    /**
     * The kit rejects a contract whose other session never counted, rather than
     * passing its revocation.
     *
     * @return void
     */
    public function testRejectsAnOtherSessionThatNeverCounted(): void
    {
        $this->expectException(AssertionFailedError::class);

        SessionRevokerContract::assertRemovingAFactorStopsAnotherSessionCounting(
            $this->sessionRevoker(),
            $this->revokedIdentity(),
            self::REMOVED_FACTOR,
            SignInProofs::SESSION,
            static function (MultiFactorAuthenticatable $identity): void {
                // Verifies nothing.
            },
            $this->doesAnotherSessionCount(...),
        );
    }

    /**
     * The bound default.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\SessionRevoker
     */
    #[\Override]
    protected function sessionRevoker(): SessionRevoker
    {
        return $this->container()->make(SessionRevoker::class);
    }

    /**
     * A person signed in on the application.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    #[\Override]
    protected function revokedIdentity(): MultiFactorAuthenticatable
    {
        /** @var \Tests\Fixtures\Identities\TestUser $user */
        $user = TestUser::query()->firstOrCreate(['email' => 'revoked@example.test']);

        $this->actingAs($user);
        $this->container()->make(ProofStore::class)->begin($user, SignInProofs::APPLICATION, SignInProofs::SESSION);

        return $user;
    }

    /**
     * The factor the kit's removals name.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return string
     */
    #[\Override]
    protected function removedFactorId(MultiFactorAuthenticatable $identity): string
    {
        return self::REMOVED_FACTOR;
    }

    /**
     * Verify the identity on its current sign-in, and name it.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return string
     */
    #[\Override]
    protected function currentSessionOf(MultiFactorAuthenticatable $identity): string
    {
        $proofs = SignInProofs::of($identity)->underGeneration(VerificationGeneration::current($identity));
        $store  = $this->container()->make(ProofStore::class);

        $store->record($proofs->password());
        $store->record($proofs->totp());

        return SignInProofs::SESSION;
    }

    /**
     * Whether the current sign-in's proofs still count.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return bool
     */
    #[\Override]
    protected function doesCurrentSessionCount(MultiFactorAuthenticatable $identity): bool
    {
        return $this->container()->make(ProofStore::class)->proofs($identity, SignInProofs::APPLICATION) !== [];
    }

    /**
     * Verify the identity on its other device.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return void
     */
    #[\Override]
    protected function verifyAnotherSession(MultiFactorAuthenticatable $identity): void
    {
        $proofs = SignInProofs::of($identity)->inSession('other-sign-in')->underGeneration(VerificationGeneration::current($identity));

        $this->otherDevice->begin($identity, SignInProofs::APPLICATION, 'other-sign-in');
        $this->otherDevice->record($proofs->password());
        $this->otherDevice->record($proofs->totp());
    }

    /**
     * Whether the other device's proofs still count.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return bool
     */
    #[\Override]
    protected function doesAnotherSessionCount(MultiFactorAuthenticatable $identity): bool
    {
        return $this->otherDevice->proofs($identity, SignInProofs::APPLICATION) !== [];
    }
}
