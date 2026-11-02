<?php

declare(strict_types = 1);

namespace Tests\Feature\Lifecycle;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\SelfServiceRecovery;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Lifecycle\LifecycleBindings;
use SineMacula\Laravel\Mfa\Lifecycle\NoSelfServiceRecovery;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\Lifecycle\Concerns\ArrangesLifecycle;
use Tests\TestCase;

/**
 * The default `SelfServiceRecovery`: none is offered, starting one is refused,
 * and nothing changes. An application's own binding replaces it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(NoSelfServiceRecovery::class)]
#[CoversClass(LifecycleBindings::class)]
final class SelfServiceRecoveryTest extends TestCase
{
    use ArrangesLifecycle;

    /**
     * By default no recovery is offered, and starting one refuses with its own
     * reason and changes nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheDefaultOffersNoneAndChangesNothing(): void
    {
        $this->arrangeLifecycle();

        $user   = $this->signedInPerson();
        $factor = $this->confirmedFactor($user);
        $seam   = $this->container()->make(SelfServiceRecovery::class);

        self::assertInstanceOf(NoSelfServiceRecovery::class, $seam);
        self::assertTrue($this->container()->isShared(SelfServiceRecovery::class));
        self::assertFalse($seam->isOffered($user, self::APPLICATION));

        try {
            $seam->start($user, self::APPLICATION);
            self::fail('Starting a recovery that is not offered was expected to be refused.');
        } catch (OperationRefusedException $exception) {
            self::assertSame(FailureReason::SELF_SERVICE_RECOVERY_UNAVAILABLE, $exception->reason);
            self::assertSame('self_service_recovery_unavailable', $exception->reason->value);
        }

        self::assertSame([$factor->id], Factor::query()->pluck('id')->all());
        self::assertSame([], $this->reportedNames());
    }
}
