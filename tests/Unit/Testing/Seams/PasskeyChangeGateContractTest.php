<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing\Seams;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Assurance\ObservedProperties;
use SineMacula\Laravel\Mfa\Context\CallerContext;
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

    /** @var ?string The gate call whose hook swallows the gate's refusal, if any. */
    private ?string $swallows = null;

    /** @var ?string The gate call whose hook makes it in a transaction of its own, if any. */
    private ?string $ownTransaction = null;

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
     * The kit rejects a path that opens a transaction of its own around the
     * gate's `registering()`.
     *
     * @return void
     */
    public function testRejectsARegistrationCallInATransactionOfItsOwn(): void
    {
        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('The path must refuse to register a passkey outside the caller\'s transaction.');

        $this->ownTransaction = 'registering';

        PasskeyChangeGateContract::assertTheGateNeedsTheCallersTransaction($this->registeringCall(), $this->removalCall());
    }

    /**
     * The kit rejects a path that opens a transaction of its own around the
     * gate's `removing()`, though its registration call is sound.
     *
     * @return void
     */
    public function testRejectsARemovalCallInATransactionOfItsOwn(): void
    {
        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('The path must refuse to remove a passkey outside the caller\'s transaction.');

        $this->ownTransaction = 'removing';

        PasskeyChangeGateContract::assertTheGateNeedsTheCallersTransaction($this->registeringCall(), $this->removalCall());
    }

    /**
     * The kit rejects a path that swallows the gate's refusal of a call outside
     * a transaction.
     *
     * @return void
     */
    public function testRejectsACallThatSwallowsTheGatesRefusal(): void
    {
        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('The path must refuse to remove a passkey outside the caller\'s transaction.');

        $this->swallows = 'removing';

        PasskeyChangeGateContract::assertTheGateNeedsTheCallersTransaction($this->registeringCall(), $this->removalCall());
    }

    /**
     * The kit refuses to make the check inside a transaction, where a sound
     * path's calls would not be refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRejectsACheckMadeInsideATransaction(): void
    {
        $connection = DB::connection(StorageConnection::name());

        $connection->beginTransaction();

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('The check must be made outside any transaction on the storage connection.');

        try {
            PasskeyChangeGateContract::assertTheGateNeedsTheCallersTransaction($this->registeringCall(), $this->removalCall());
        } finally {
            $connection->rollBack();
        }
    }

    /**
     * The kit's test hands the contract the test case's own registration hook,
     * so one that swallows the gate's refusal fails it.
     *
     * @return void
     */
    public function testTheKitCallsTheRegistrationHook(): void
    {
        $this->swallows = 'registering';

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('The path must refuse to register a passkey outside the caller\'s transaction.');

        $this->testPasskeyChangeGateNeedsTheCallersTransaction();
    }

    /**
     * The kit's test hands the contract the test case's own removal hook, so
     * one that swallows the gate's refusal fails it.
     *
     * @return void
     */
    public function testTheKitCallsTheRemovalHook(): void
    {
        $this->swallows = 'removing';

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('The path must refuse to remove a passkey outside the caller\'s transaction.');

        $this->testPasskeyChangeGateNeedsTheCallersTransaction();
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
        $registrar = new StandInRegistrar($this->container()->make(PasskeyChangeGate::class));

        return $registrar->register($identity, self::APPLICATION, $this->registration($identity, self::APPLICATION, $credentialId));
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

    /**
     * Call the gate's `registering()` as an adapter would, broken as the test
     * says.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $credentialId
     * @return mixed
     */
    #[\Override]
    protected function gateRegistering(MultiFactorAuthenticatable $identity, string $application, #[\SensitiveParameter] string $credentialId): mixed
    {
        $call = fn (): mixed => $this->container()->make(PasskeyChangeGate::class)->registering(
            CallerContext::forIdentity($identity, $application),
            $this->registration($identity, $application, $credentialId),
        );

        return $this->asBroken('registering', $call);
    }

    /**
     * Call the gate's `removing()` as an adapter would, broken as the test
     * says.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $credentialId
     * @return mixed
     */
    #[\Override]
    protected function gateRemoving(MultiFactorAuthenticatable $identity, string $application, #[\SensitiveParameter] string $credentialId): mixed
    {
        $call = fn (): mixed => $this->container()->make(PasskeyChangeGate::class)->removing(CallerContext::forIdentity($identity, $application), $credentialId);

        return $this->asBroken('removing', $call);
    }

    /**
     * A registration of the credential for the identity on the application.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $credentialId
     * @return \SineMacula\Laravel\Mfa\Passkeys\PasskeyRegistration
     */
    private function registration(MultiFactorAuthenticatable $identity, string $application, #[\SensitiveParameter] string $credentialId): PasskeyRegistration
    {
        $owner = ProofOwner::of($identity);

        return new PasskeyRegistration(
            $credentialId,
            new ObservedProperties(userPresence: true),
            new ProofBinding($owner->type, $owner->key, $application, self::SESSION, Purpose::ENROLLMENT),
        );
    }

    /**
     * The gate's `registering()` for the person on the application, as the
     * adapter's call.
     *
     * @return \Closure(string): mixed
     */
    private function registeringCall(): \Closure
    {
        return fn (#[\SensitiveParameter] string $credentialId): mixed => $this->gateRegistering($this->user, self::APPLICATION, $credentialId);
    }

    /**
     * The gate's `removing()` for the person on the application, as the
     * adapter's call.
     *
     * @return \Closure(string): mixed
     */
    private function removalCall(): \Closure
    {
        return fn (#[\SensitiveParameter] string $credentialId): mixed => $this->gateRemoving($this->user, self::APPLICATION, $credentialId);
    }

    /**
     * Make the hook's call as the test says: in a transaction of its own, with
     * a `LogicException` swallowed, or as it is.
     *
     * @param  string  $hook
     * @param  \Closure(): mixed  $call
     * @return mixed
     */
    private function asBroken(string $hook, \Closure $call): mixed
    {
        if ($this->ownTransaction === $hook) {
            return DB::connection(StorageConnection::name())->transaction($call);
        }

        if ($this->swallows !== $hook) {
            return $call();
        }

        try {
            return $call();
        } catch (\LogicException) {
            return null;
        }
    }
}
