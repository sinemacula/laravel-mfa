<?php

declare(strict_types = 1);

namespace Tests\Unit\Requirements;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\FreshnessGate;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Contracts\Reauthenticator;
use SineMacula\Laravel\Mfa\Enums\FactorChange;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Requirements\ConfiguredFactorChangeGate;
use SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest;
use Tests\Fixtures\Factors\FactorSets;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Lifecycle\FixedFreshnessGate;
use Tests\Fixtures\Requirements\Concerns\ArrangesFactorChanges;
use Tests\Fixtures\Requirements\SignInProofs;
use Tests\Fixtures\Seams\FreshReauthenticator;
use Tests\TestCase;

/**
 * Tests for `ConfiguredFactorChangeGate`: a further factor, a removal and new
 * recovery codes rest on a step-up fresh for their operation, a removal on one
 * made without the factor while another confirmed factor remains, and a first
 * additional factor on the first factor proved again on the sign-in within five
 * minutes. Its refusals are the package's `not_fresh`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConfiguredFactorChangeGate::class)]
final class ConfiguredFactorChangeGateTest extends TestCase
{
    use ArrangesFactorChanges;

    /**
     * Fix the time to a whole second.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        CarbonImmutable::setTestNow(CarbonImmutable::now()->startOfSecond());
    }

    /**
     * Release the fixed time.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * A grant lasts as long as its freshness: a further factor as long as the
     * step-up is fresh for `mfa.add_factor`, a first one five minutes from the
     * reauthentication; the other changes answer no end.
     *
     * @return void
     */
    public function testEachChangesAnswer(): void
    {
        $user = $this->steppedUp();

        $this->container()->instance(Reauthenticator::class, new FreshReauthenticator($this->container()->make(ProofStore::class), 60));

        self::assertEquals(CarbonImmutable::now()->addSeconds(900), $this->authorize($this->changeRequest($user, FactorChange::ADD_FACTOR, null)));
        self::assertEquals(CarbonImmutable::now()->addSeconds(240), $this->authorize($this->changeRequest($user, FactorChange::ADD_FIRST_ADDITIONAL_FACTOR, null)));
        self::assertNull($this->authorize($this->changeRequest($user, FactorChange::REMOVE_FACTOR, self::OTHER_FACTOR)));
        self::assertNull($this->authorize($this->changeRequest($user, FactorChange::GENERATE_RECOVERY_CODES, null)));
    }

    /**
     * A stale session is refused every change, as the package's `not_fresh`, a
     * removal of the only factor included.
     *
     * @return void
     */
    public function testAStaleSessionIsRefusedEveryChange(): void
    {
        $user  = $this->signInWith(static fn (SignInProofs $signIn): array => [$signIn->password(7200)]);
        $alone = FactorSets::of(self::factorWith(self::STEPPED_UP_WITH));

        foreach (FactorChange::cases() as $change) {
            $this->assertRefused($this->changeRequest($user, $change, $change->namesFactor() ? self::OTHER_FACTOR : null));
        }

        $this->assertRefused($this->changeRequest($user, FactorChange::REMOVE_FACTOR, self::STEPPED_UP_WITH, null, $alone));
    }

    /**
     * A step-up made with the factor authorises its removal while no other
     * confirmed factor remains, a pending one included; with another confirmed
     * factor it does not.
     *
     * @return void
     */
    public function testAFactorAuthorizesItsOwnRemovalOnlyWhileNoOtherIsConfirmed(): void
    {
        $user    = $this->steppedUp();
        $alone   = FactorSets::of(self::factorWith(self::STEPPED_UP_WITH));
        $pending = FactorSets::of(self::factorWith(self::STEPPED_UP_WITH), self::factorWith(self::OTHER_FACTOR, 'pending'));

        self::assertNull($this->authorize($this->changeRequest($user, FactorChange::REMOVE_FACTOR, self::STEPPED_UP_WITH, null, $alone)));
        self::assertNull($this->authorize($this->changeRequest($user, FactorChange::REMOVE_FACTOR, self::STEPPED_UP_WITH, null, $pending)));

        $this->assertRefused($this->changeRequest($user, FactorChange::REMOVE_FACTOR, self::STEPPED_UP_WITH));
    }

    /**
     * While another confirmed factor remains, a freshness gate with no
     * requirement to judge the removal by refuses it, fresh as it says the
     * session is.
     *
     * @return void
     */
    public function testAFreshnessGateWithNoRequirementRefusesARemovalWhileAnotherFactorRemains(): void
    {
        $user = $this->steppedUp();

        $this->container()->instance(FreshnessGate::class, new FixedFreshnessGate(null));

        $this->assertRefused($this->changeRequest($user, FactorChange::REMOVE_FACTOR, self::OTHER_FACTOR));
    }

    /**
     * A first additional factor is refused a reauthentication of another
     * sign-in, one dated in the future, and one older than five minutes.
     *
     * @return void
     */
    public function testAFirstFactorIsRefusedAReauthenticationThatDoesNotCount(): void
    {
        $user  = $this->steppedUp();
        $store = $this->container()->make(ProofStore::class);

        foreach ([new FreshReauthenticator($store, 0, 'another-sign-in'), new FreshReauthenticator($store, -60), new FreshReauthenticator($store, 301)] as $reauthenticator) {
            $this->container()->instance(Reauthenticator::class, $reauthenticator);

            $this->assertRefused($this->changeRequest($user, FactorChange::ADD_FIRST_ADDITIONAL_FACTOR, null));
        }
    }

    /**
     * A person who stepped up just now with a TOTP code, after a password an
     * hour ago.
     *
     * @return \Tests\Fixtures\Identities\TestUser
     */
    private function steppedUp(): TestUser
    {
        return $this->signInWith(static fn (SignInProofs $signIn): array => [$signIn->password(3600), $signIn->totp()]);
    }

    /**
     * Ask the gate under test.
     *
     * @param  \SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest  $request
     * @return ?\Carbon\CarbonImmutable
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    private function authorize(FactorChangeRequest $request): ?CarbonImmutable
    {
        return $this->container()->make(ConfiguredFactorChangeGate::class)->authorize($request);
    }

    /**
     * The gate refuses the request as the package's `not_fresh`.
     *
     * @param  \SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest  $request
     * @return void
     */
    private function assertRefused(FactorChangeRequest $request): void
    {
        try {
            $this->authorize($request);
            self::fail(sprintf('The change [%s] was expected to be refused.', $request->change->value));
        } catch (OperationRefusedException $exception) {
            self::assertSame(FailureReason::NOT_FRESH, $exception->reason);
            self::assertTrue($exception->byPackage);
        }
    }
}
