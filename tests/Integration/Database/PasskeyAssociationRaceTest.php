<?php

declare(strict_types = 1);

namespace Tests\Integration\Database;

use Illuminate\Config\Repository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Contracts\Reauthenticator;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Models\PasskeyAssociation;
use SineMacula\Laravel\Mfa\Models\RecoveryCode;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyAssociations;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyChangeGate;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Passkeys\Concerns\ArrangesPasskeys;
use Tests\Fixtures\Passkeys\StandInRegistrar;
use Tests\Fixtures\Seams\FreshReauthenticator;
use Tests\Integration\Database\Concerns\RacesAForkedWorker;
use Tests\TestCase;

/**
 * Two identities register one credential at once, each under its own lock, so
 * only the credential's unique index stands between them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PasskeyChangeGate::class)]
#[CoversClass(PasskeyAssociations::class)]
final class PasskeyAssociationRaceTest extends TestCase
{
    use ArrangesPasskeys, RacesAForkedWorker;

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        if (!in_array(DB::connection()->getDriverName(), ['mysql', 'pgsql'], true)) {
            self::markTestSkipped('Concurrent registrations are proven on MySQL and PostgreSQL.');
        }

        $this->needsAFork();
        $this->enablePasskeys(['recovery_codes' => ['enabled' => true]]);

        $this->container()->instance(Reauthenticator::class, new FreshReauthenticator($this->container()->make(ProofStore::class)));
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheSecondRegistrationIsRefusedOnceTheFirstCommits(): void
    {
        $owner    = $this->signedInPerson('owner@example.test');
        $intruder = $this->signedInPerson('intruder@example.test');

        $outcome = $this->holdingTheLock(
            fn () => self::assertNull($this->register($owner)),
            fn (): ?FailureReason => $this->register($intruder),
        );

        self::assertSame(FailureReason::CREDENTIAL_ASSOCIATED->value, $outcome);
        $this->assertOnlyRegisteredFor($owner, $intruder);
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheSecondRegistrationIsAssociatedWhenTheFirstRollsBack(): void
    {
        $owner    = $this->signedInPerson('owner@example.test');
        $intruder = $this->signedInPerson('intruder@example.test');

        $outcome = $this->holdingTheLock(
            fn () => self::assertNull($this->register($owner)),
            fn (): ?FailureReason => $this->register($intruder),
            commit: false,
        );

        self::assertSame('made', $outcome);
        $this->assertOnlyRegisteredFor($intruder, $owner);
    }

    /**
     * @param  mixed  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(Repository::class);

        $config->set('database.connections.observer', $config->get('database.connections.testing'));
        $config->set('database.connections.racer', $config->get('database.connections.testing'));
        $config->set('hashing.bcrypt.rounds', 4);
    }

    /**
     * As the identity's own request, through the stand-in layer's transaction.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $identity
     * @return ?\SineMacula\Laravel\Mfa\Enums\FailureReason
     *
     * @throws \Throwable
     */
    private function register(TestUser $identity): ?FailureReason
    {
        $this->actingAs($identity);

        try {
            (new StandInRegistrar($this->container()->make(PasskeyChangeGate::class)))->register($identity, self::APPLICATION, $this->registration($identity));
        } catch (OperationRefusedException $exception) {
            return $exception->reason;
        }

        return null;
    }

    /**
     * @param  \Tests\Fixtures\Identities\TestUser  $holder
     * @param  \Tests\Fixtures\Identities\TestUser  $other
     * @return void
     */
    private function assertOnlyRegisteredFor(TestUser $holder, TestUser $other): void
    {
        $holderKey   = ProofOwner::of($holder)->key;
        $association = PasskeyAssociation::query()->sole();
        $factor      = Factor::query()->sole();

        self::assertSame($holderKey, $association->authenticatable_id);
        self::assertSame($factor->id, $association->factor_id);
        self::assertSame($holderKey, $factor->authenticatable_id);
        self::assertTrue(StandInRegistrar::stores($holder, self::CREDENTIAL));
        self::assertFalse(StandInRegistrar::stores($other, self::CREDENTIAL));
        self::assertSame(10, RecoveryCode::query()->where('authenticatable_id', $holderKey)->count());
        self::assertSame(0, RecoveryCode::query()->where('authenticatable_id', ProofOwner::of($other)->key)->count());
    }
}
