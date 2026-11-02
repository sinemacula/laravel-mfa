<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing\Seams;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Assurance\ObservedProperties;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Contracts\Reauthenticator;
use SineMacula\Laravel\Mfa\Database\StorageConnection;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Models\PasskeyAssociation;
use SineMacula\Laravel\Mfa\Passkeys\CredentialId;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyChangeGate;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyRegistration;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Testing\Seams\Concerns\PasskeyChangeGateTests;
use SineMacula\Laravel\Mfa\Testing\Seams\PasskeyChangeGateContract;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Passkeys\Concerns\ArrangesPasskeys;
use Tests\Fixtures\Passkeys\StandInRegistrar;
use Tests\Fixtures\Seams\FreshReauthenticator;
use Tests\TestCase;

/**
 * The passkey change gate wiring kit proves a registration path that calls the
 * gate inside its own transaction, and rejects one that swallows the gate's
 * refusal and keeps its credential.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PasskeyChangeGateContract::class)]
#[CoversClass(PasskeyChangeGate::class)]
final class PasskeyChangeGateContractTest extends TestCase
{
    use ArrangesPasskeys, PasskeyChangeGateTests;

    /** @var \Tests\Fixtures\Identities\TestUser The person registering passkeys. */
    private TestUser $user;

    /**
     * Enable passkeys, sign a person in, and let them prove their password
     * again.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->enablePasskeys();

        $this->user = $this->signedInPerson();

        $this->container()->instance(Reauthenticator::class, new FreshReauthenticator($this->container()->make(ProofStore::class)));
    }

    /**
     * The kit rejects a path that swallows the gate's refusal and keeps its
     * credential.
     *
     * @return void
     */
    public function testRejectsAPathThatSwallowsTheRefusal(): void
    {
        $swallowing = function (MultiFactorAuthenticatable $identity, string $credentialId): bool {
            try {
                $this->registerPasskey($identity, $credentialId);
            } catch (OperationRefusedException) {
                StandInRegistrar::store($identity, $credentialId);
            }

            return true;
        };

        $this->expectException(AssertionFailedError::class);

        PasskeyChangeGateContract::assertARefusedGateRollsBackTheRegistration($this->user, $swallowing, StandInRegistrar::stores(...));
    }

    /**
     * The kit rejects a path that swallows the gate's refusal, even one that
     * then keeps nothing.
     *
     * @return void
     */
    public function testRejectsAPathThatSucceedsDespiteTheRefusal(): void
    {
        $quiet = function (MultiFactorAuthenticatable $identity, string $credentialId): bool {
            try {
                $this->registerPasskey($identity, $credentialId);
            } catch (OperationRefusedException) {
                // Swallowed: the path reports success.
            }

            return true;
        };

        $this->expectException(AssertionFailedError::class);

        PasskeyChangeGateContract::assertARefusedGateRollsBackTheRegistration($this->user, $quiet, StandInRegistrar::stores(...));
    }

    /**
     * The kit rejects a path that keeps the credential outside its own
     * transaction before the gate refuses.
     *
     * @return void
     */
    public function testRejectsAPathThatKeepsTheCredentialOutsideItsTransaction(): void
    {
        $early = function (MultiFactorAuthenticatable $identity, string $credentialId): mixed {
            StandInRegistrar::store($identity, $credentialId);

            return $this->registerPasskey($identity, $credentialId);
        };

        $this->expectException(AssertionFailedError::class);

        PasskeyChangeGateContract::assertARefusedGateRollsBackTheRegistration($this->user, $early, StandInRegistrar::stores(...));
    }

    /**
     * The kit rejects a path that associates the credential itself, outside the
     * gate, before the gate refuses.
     *
     * @return void
     */
    public function testRejectsAPathThatAssociatesOutsideTheGate(): void
    {
        $associating = function (MultiFactorAuthenticatable $identity, string $credentialId): mixed {
            $owner = ProofOwner::of($identity);

            (new PasskeyAssociation([
                'factor_id'            => 'path-factor',
                'authenticatable_type' => $owner->type,
                'authenticatable_id'   => $owner->key,
                'credential_id_hash'   => CredentialId::hash('cGF0aC1jcmVkZW50aWFs'),
                'credential_id'        => 'cGF0aC1jcmVkZW50aWFs',
            ]))->save();

            return $this->registerPasskey($identity, $credentialId);
        };

        $this->expectException(AssertionFailedError::class);

        PasskeyChangeGateContract::assertARefusedGateRollsBackTheRegistration($this->user, $associating, StandInRegistrar::stores(...));
    }

    /**
     * The kit rejects a gate that needs no transaction of the caller's to join,
     * shown by calling it inside one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRejectsAGateThatNeedsNoTransaction(): void
    {
        $connection = DB::connection(StorageConnection::name());

        $connection->beginTransaction();

        $this->expectException(AssertionFailedError::class);

        try {
            PasskeyChangeGateContract::assertTheGateNeedsTheCallersTransaction($this->user, self::APPLICATION);
        } finally {
            $connection->rollBack();
        }
    }

    /**
     * The person.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    #[\Override]
    protected function gatedIdentity(): MultiFactorAuthenticatable
    {
        return $this->user;
    }

    /**
     * The application.
     *
     * @return string
     */
    #[\Override]
    protected function gatedApplication(): string
    {
        return self::APPLICATION;
    }

    /**
     * Register the credential through the stand-in registrar.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $credentialId
     * @return mixed
     *
     * @throws \Throwable
     */
    #[\Override]
    protected function registerPasskey(MultiFactorAuthenticatable $identity, #[\SensitiveParameter] string $credentialId): mixed
    {
        $owner = ProofOwner::of($identity);

        $registration = new PasskeyRegistration(
            $credentialId,
            new ObservedProperties(userPresence: true),
            new ProofBinding($owner->type, $owner->key, self::APPLICATION, self::SESSION, Purpose::ENROLLMENT),
        );

        return (new StandInRegistrar($this->container()->make(PasskeyChangeGate::class)))->register($identity, self::APPLICATION, $registration);
    }

    /**
     * Whether the stand-in registrar kept the credential.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $credentialId
     * @return bool
     */
    #[\Override]
    protected function isPasskeyStored(MultiFactorAuthenticatable $identity, #[\SensitiveParameter] string $credentialId): bool
    {
        return StandInRegistrar::stores($identity, $credentialId);
    }
}
