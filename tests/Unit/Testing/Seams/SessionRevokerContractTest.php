<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing\Seams;

use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Contracts\SessionRevoker;
use SineMacula\Laravel\Mfa\Proofs\GenerationSessionRevoker;
use SineMacula\Laravel\Mfa\Proofs\SessionProofStore;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;
use SineMacula\Laravel\Mfa\Testing\Seams\SessionRevokerContract;
use SineMacula\Laravel\Mfa\Testing\Seams\SessionRevokerTests;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Requirements\SignInProofs;
use Tests\Fixtures\Seams\FaultySeams;
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

        SessionRevokerContract::assertRevokingOthersStopsAnotherSessionCounting(new FaultySeams, $this->revokedIdentity(), $this->verifyAnotherSession(...), $this->anotherSessionCounts(...));
    }

    /**
     * The bound default.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\SessionRevoker
     */
    protected function sessionRevoker(): SessionRevoker
    {
        return $this->container()->make(SessionRevoker::class);
    }

    /**
     * A person signed in on the application.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    protected function revokedIdentity(): MultiFactorAuthenticatable
    {
        /** @var \Tests\Fixtures\Identities\TestUser $user */
        $user = TestUser::query()->firstOrCreate(['email' => 'revoked@example.test']);

        $this->actingAs($user);
        $this->container()->make(ProofStore::class)->begin($user, SignInProofs::APPLICATION, SignInProofs::SESSION);

        return $user;
    }

    /**
     * Verify the identity on its other device.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return void
     */
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
    protected function anotherSessionCounts(MultiFactorAuthenticatable $identity): bool
    {
        return $this->otherDevice->proofs($identity, SignInProofs::APPLICATION) !== [];
    }
}
