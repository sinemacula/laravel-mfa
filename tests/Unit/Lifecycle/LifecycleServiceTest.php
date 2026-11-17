<?php

declare(strict_types = 1);

namespace Tests\Unit\Lifecycle;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\SubjectTypeResolver;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Lifecycle\LifecycleService;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Models\IdentityState;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use Tests\Fixtures\Lifecycle\Concerns\ArrangesLifecycle;
use Tests\TestCase;

/**
 * The operator helpers refuse a machine identity before touching anything.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LifecycleService::class)]
final class LifecycleServiceTest extends TestCase
{
    use ArrangesLifecycle;

    /**
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeLifecycle();
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testAMachineIsRefusedByEveryOperatorHelper(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->confirmedFactor($user);
        $types  = self::createStub(SubjectTypeResolver::class);
        $until  = CarbonImmutable::now()->addHour();
        $owner  = ProofOwner::of($user);

        $factor->update(['disabled_at' => CarbonImmutable::now(), 'locked_until' => $until]);

        IdentityState::query()->create(['authenticatable_type' => $owner->type, 'authenticatable_id' => $owner->key, 'consecutive_failures' => 7, 'locked_until' => $until]);

        $types->method('isPerson')->willReturn(false);

        $this->container()->instance(SubjectTypeResolver::class, $types);

        $calls = [
            static fn (): bool => Mfa::unlockFactor($user, $factor->id, self::actor()),
            static fn (): bool => Mfa::unlockFactor($user, 'missing', self::actor()),
            static fn (): bool => Mfa::enableFactor($user, $factor->id, self::actor()),
            static fn (): bool => Mfa::unlockIdentity($user, self::actor()),
        ];

        foreach ($calls as $call) {
            try {
                $call();
                self::fail('A machine was expected to be refused.');
            } catch (OperationRefusedException $exception) {
                self::assertSame(FailureReason::MACHINE_IDENTITY, $exception->reason);
            }
        }

        $stored = Factor::query()->whereKey($factor->id)->sole();
        $state  = IdentityState::query()->sole();

        self::assertNotNull($stored->getDisabledAt());
        self::assertNotNull($stored->getLockedUntil());
        self::assertSame(7, $state->consecutive_failures);
        self::assertSame($until->getTimestamp(), $state->locked_until?->getTimestamp());
        self::assertSame([], $this->reportedNames());
    }
}
