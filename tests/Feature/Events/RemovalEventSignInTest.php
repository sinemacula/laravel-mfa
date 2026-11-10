<?php

declare(strict_types = 1);

namespace Tests\Feature\Events;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\EventContextResolver;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Events\EventDispatcher;
use SineMacula\Laravel\Mfa\Events\FactorRemoved;
use SineMacula\Laravel\Mfa\Events\RecoveryCodesRemoved;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Lifecycle\FactorRemoval;
use SineMacula\Laravel\Mfa\Lifecycle\FactorRemovalResult;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Factors\FactorSets;
use Tests\Fixtures\Lifecycle\Concerns\ArrangesLifecycle;
use Tests\Fixtures\Seams\RecordingEventContextResolver;
use Tests\TestCase;

/**
 * A factor's removal names the sign-in it was made from, and so does the end of
 * the recovery code set that goes with the last confirmed factor: the sign-in
 * the removal is given, not the one the proof store holds for the identity.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EventDispatcher::class)]
#[CoversClass(FactorRemoval::class)]
#[CoversClass(RecoveryCodeService::class)]
final class RemovalEventSignInTest extends TestCase
{
    use ArrangesLifecycle;

    /** @var string A sign-in other than the one the proof store holds. */
    private const string ELSEWHERE = 'sign-in-elsewhere';

    /**
     * Arrange the application and bind the recording resolver.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeLifecycle();

        $this->container()->instance(EventContextResolver::class, new RecordingEventContextResolver);
    }

    /**
     * Removing the last confirmed factor names the sign-in the removal is
     * given, on the factor's removal and on its recovery code set's, though the
     * proof store holds another.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARemovalNamesTheSignInItIsGiven(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->confirmedFactor($user);

        $this->recoveryCodesOf($user);

        $removal = $this->container()->make(FactorRemoval::class);
        $result  = DB::transaction(static fn (): FactorRemovalResult => $removal->remove($user, self::APPLICATION, $factor, FactorSets::of($factor), self::ELSEWHERE));

        self::assertTrue($result->wasMade());
        self::assertSame([self::ELSEWHERE], RecordingEventContextResolver::signInsOf($this->reported, FactorRemoved::class));
        self::assertSame([self::ELSEWHERE], RecordingEventContextResolver::signInsOf($this->reported, RecoveryCodesRemoved::class));
        self::assertSame(self::SESSION, $this->container()->make(ProofStore::class)->currentSession($user, self::APPLICATION));
    }

    /**
     * A person removing their last confirmed factor names the sign-in the
     * removal is bound to, on both events.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACallersRemovalNamesItsSignIn(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->confirmedFactor($user);

        $this->recoveryCodesOf($user);
        $this->stepUpWith($user, $factor);

        self::assertTrue(Mfa::removeFactor(Callers::current(), $factor->id)->wasMade());
        self::assertSame([self::SESSION], RecordingEventContextResolver::signInsOf($this->reported, FactorRemoved::class));
        self::assertSame([self::SESSION], RecordingEventContextResolver::signInsOf($this->reported, RecoveryCodesRemoved::class));
    }
}
