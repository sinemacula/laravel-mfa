<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing\Seams;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\FactorChangeGate;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Contracts\Reauthenticator;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Enums\FactorChange;
use SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Testing\Seams\Concerns\FactorChangeGateTests;
use SineMacula\Laravel\Mfa\Testing\Seams\FactorChangeGateContract;
use Tests\Fixtures\Requirements\Concerns\ArrangesFactorChanges;
use Tests\Fixtures\Requirements\ScriptedFactorChangeGate;
use Tests\Fixtures\Requirements\SignInProofs;
use Tests\Fixtures\Seams\FreshReauthenticator;
use Tests\TestCase;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FactorChangeGateContract::class)]
final class FactorChangeGateContractTest extends TestCase
{
    use ArrangesFactorChanges, FactorChangeGateTests;

    /**
     * @return void
     */
    public function testRejectsAGateThatAllowsAStaleChange(): void
    {
        $this->expectException(AssertionFailedError::class);

        FactorChangeGateContract::assertAStaleChangeIsRefused($this->allowingGate(), $this->staleChange(FactorChange::ADD_FACTOR));
    }

    /**
     * @return void
     */
    public function testRejectsAGateThatRefusesWithAnotherException(): void
    {
        $this->expectException(AssertionFailedError::class);

        FactorChangeGateContract::assertAStaleChangeIsRefused(new ScriptedFactorChangeGate(refusal: new \RuntimeException('No.')), $this->staleChange(FactorChange::REMOVE_FACTOR));
    }

    /**
     * @return void
     */
    public function testRejectsAGateThatLetsAFactorAuthorizeItsOwnRemoval(): void
    {
        $this->expectException(AssertionFailedError::class);

        FactorChangeGateContract::assertAFactorNeverAuthorizesItsOwnRemoval($this->allowingGate(), $this->removalSteppedUpOnlyWithTheFactor());
    }

    /**
     * @return void
     */
    public function testRejectsAGateTheConfiguredRequirementDoesNotBind(): void
    {
        $this->expectException(AssertionFailedError::class);

        FactorChangeGateContract::assertTheConfiguredRequirementBinds($this->allowingGate(), $this->changeBeyondTheConfiguredRequirement());
    }

    /**
     * @return void
     */
    public function testRejectsAGrantWithNoEnd(): void
    {
        $this->expectException(AssertionFailedError::class);

        FactorChangeGateContract::assertAFreshChangeIsAllowed(new ScriptedFactorChangeGate, $this->freshChange(FactorChange::ADD_FACTOR));
    }

    /**
     * @return void
     */
    public function testRejectsAGrantThatHasEnded(): void
    {
        $gate = new ScriptedFactorChangeGate(CarbonImmutable::now()->subSecond());

        $this->expectException(AssertionFailedError::class);

        FactorChangeGateContract::assertAFreshChangeIsAllowed($gate, $this->freshChange(FactorChange::ADD_FIRST_ADDITIONAL_FACTOR));
    }

    /**
     * @return void
     */
    public function testAChangeThatIsNoGrantNeedsNoEnd(): void
    {
        FactorChangeGateContract::assertAFreshChangeIsAllowed(new ScriptedFactorChangeGate, $this->freshChange(FactorChange::GENERATE_RECOVERY_CODES));

        $this->addToAssertionCount(1);
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Contracts\FactorChangeGate
     */
    #[\Override]
    protected function factorChangeGate(): FactorChangeGate
    {
        return $this->container()->make(FactorChangeGate::class);
    }

    /**
     * Stepped up just now with TOTP after a password, and proved the password
     * again just now.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\FactorChange  $change
     * @return \SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest
     */
    #[\Override]
    protected function freshChange(FactorChange $change): FactorChangeRequest
    {
        $user = $this->signInWith(static fn (SignInProofs $signIn): array => [$signIn->password(), $signIn->totp()]);

        $this->container()->instance(Reauthenticator::class, new FreshReauthenticator($this->container()->make(ProofStore::class)));

        return $this->changeRequest($user, $change, $change->namesFactor() ? self::OTHER_FACTOR : null);
    }

    /**
     * Signed in two hours ago with a password and proved nothing since.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\FactorChange  $change
     * @return \SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest
     */
    #[\Override]
    protected function staleChange(FactorChange $change): FactorChangeRequest
    {
        $user = $this->signInWith(static fn (SignInProofs $signIn): array => [$signIn->password(7200)]);

        $this->container()->forgetInstance(Reauthenticator::class);

        return $this->changeRequest($user, $change, $change->namesFactor() ? self::OTHER_FACTOR : null);
    }

    /**
     * Stepped up just now only with the factor being removed, holding another
     * confirmed factor.
     *
     * @return \SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest
     */
    #[\Override]
    protected function removalSteppedUpOnlyWithTheFactor(): FactorChangeRequest
    {
        $user = $this->signInWith(static fn (SignInProofs $signIn): array => [$signIn->password(), $signIn->totp()]);

        return $this->changeRequest($user, FactorChange::REMOVE_FACTOR, self::STEPPED_UP_WITH);
    }

    /**
     * Stepped up just now with TOTP, for a change the application configures to
     * need AAL3.
     *
     * @return \SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest
     */
    #[\Override]
    protected function changeBeyondTheConfiguredRequirement(): FactorChangeRequest
    {
        $user = $this->signInWith(static fn (SignInProofs $signIn): array => [$signIn->password(), $signIn->totp()]);

        return $this->changeRequest($user, FactorChange::ADD_FACTOR, null, Requirement::none()->withMinimumLevel(AssuranceLevel::AAL3, 300));
    }

    /**
     * Allows every change for a minute.
     *
     * @return \Tests\Fixtures\Requirements\ScriptedFactorChangeGate
     */
    private function allowingGate(): ScriptedFactorChangeGate
    {
        return new ScriptedFactorChangeGate(CarbonImmutable::now()->addMinute());
    }
}
