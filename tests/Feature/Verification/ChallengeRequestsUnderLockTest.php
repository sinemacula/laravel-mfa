<?php

declare(strict_types = 1);

namespace Tests\Feature\Verification;

use Carbon\Carbon;
use Carbon\CarbonImmutable;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Attempts\ChallengeCounters;
use SineMacula\Laravel\Mfa\Contracts\ChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Database\TableNames;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Verification\ChallengeRequests;
use Tests\Fixtures\Identities\NonEloquentIdentity;
use Tests\Fixtures\Seams\CountingChallengeGateway;
use Tests\Fixtures\Verification\Concerns\ArrangesVerification;
use Tests\TestCase;

/**
 * A code is sent only when the counters admit the factor under the identity's
 * lock, whatever the bound challenge gateway checks itself: a locked factor,
 * and an identity found inactive once the lock is held, are refused before the
 * gateway is asked to send anything.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ChallengeRequests::class)]
#[CoversClass(ChallengeCounters::class)]
final class ChallengeRequestsUnderLockTest extends TestCase
{
    use ArrangesVerification;

    /** @var \Tests\Fixtures\Seams\CountingChallengeGateway The bound gateway, which admits anything. */
    private CountingChallengeGateway $gateway;

    /**
     * Arrange verification with a gateway that checks no admission of its own.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeVerification();

        $this->gateway = new CountingChallengeGateway;

        $this->container()->instance(ChallengeGateway::class, $this->gateway);
    }

    /**
     * Reset the time.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();

        parent::tearDown();
    }

    /**
     * A locked factor is refused as locked, and the gateway is never asked to
     * send it a code.
     *
     * @return void
     */
    public function testALockedFactorIsSentNothing(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->emailFactor($user, attributes: ['locked_until' => CarbonImmutable::now()->addMinutes(15)]);

        $result = $this->mfa()->sendCode($factor->id);

        self::assertSame(FailureReason::LOCKED, $result->reason);
        self::assertSame(0, $this->gateway->sends);
    }

    /**
     * The caller is read again once the identity's lock is held, and an
     * identity found inactive then is refused, though it was active when its
     * factor was first looked up: the gateway is never asked to send.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAnIdentityFoundInactiveOnceTheLockIsHeldIsSentNothing(): void
    {
        $active   = new NonEloquentIdentity('plain-1');
        $inactive = new NonEloquentIdentity('plain-1', active: false);
        $owner    = ProofOwner::of($active);
        $factor   = Factor::query()->create([
            'authenticatable_type' => $owner->type,
            'authenticatable_id'   => $owner->key,
            'type'                 => 'email',
            'destination'          => self::ADDRESS,
            'status'               => 'confirmed',
            'confirmed_at'         => CarbonImmutable::now(),
        ]);

        $this->actingAs($active);

        $this->container()->make(ProofStore::class)->begin($active, self::APPLICATION, self::SESSION);

        $states = TableNames::of(TableNames::IDENTITY_STATES);
        $locked = false;

        Event::listen(QueryExecuted::class, function (QueryExecuted $query) use ($inactive, $states, &$locked): void {
            if ($locked || !str_starts_with(strtolower($query->sql), 'insert') || !str_contains($query->sql, $states)) {
                return;
            }

            $locked = true;

            $this->actingAs($inactive);
        });

        $result = $this->mfa()->sendCode($factor->id);

        self::assertTrue($locked, 'The identity\'s lock was expected to be taken.');
        self::assertSame(FailureReason::IDENTITY_INACTIVE, $result->reason);
        self::assertSame(0, $this->gateway->sends);
    }
}
