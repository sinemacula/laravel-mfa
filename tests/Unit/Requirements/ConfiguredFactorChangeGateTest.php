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
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        CarbonImmutable::setTestNow(CarbonImmutable::now()->startOfSecond());
    }

    /**
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * A further factor lasts while the `mfa.add_factor` step-up is fresh, a
     * first one five minutes from the reauthentication; the other changes have
     * no end.
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
     * Refused as `not_fresh`, a removal of the only factor included.
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
     * A pending factor does not count as another.
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
     * However fresh it says the session is.
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
     * A reauthentication of another sign-in, one dated in the future, or one
     * older than five minutes.
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
     * Stepped up just now with a TOTP code, after a password an hour ago.
     *
     * @return \Tests\Fixtures\Identities\TestUser
     */
    private function steppedUp(): TestUser
    {
        return $this->signInWith(static fn (SignInProofs $signIn): array => [$signIn->password(3600), $signIn->totp()]);
    }

    /**
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
     * Refused as the package's `not_fresh`.
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
