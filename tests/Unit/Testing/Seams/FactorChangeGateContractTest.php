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
 * The `FactorChangeGate` contract kit proves the default, which judges each
 * change on the session's recorded proofs, and rejects gates that allow what
 * they must refuse, refuse some other way than the contract's, or give a grant
 * no end in the future.
 *
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
     * The kit rejects a gate that allows a change from a stale session.
     *
     * @return void
     */
    public function testRejectsAGateThatAllowsAStaleChange(): void
    {
        $this->expectException(AssertionFailedError::class);

        FactorChangeGateContract::assertAStaleChangeIsRefused($this->allowingGate(), $this->staleChange(FactorChange::ADD_FACTOR));
    }

    /**
     * The kit rejects a gate that refuses some other way than by throwing an
     * `OperationRefusedException`.
     *
     * @return void
     */
    public function testRejectsAGateThatRefusesWithAnotherException(): void
    {
        $this->expectException(AssertionFailedError::class);

        FactorChangeGateContract::assertAStaleChangeIsRefused(new ScriptedFactorChangeGate(refusal: new \RuntimeException('No.')), $this->staleChange(FactorChange::REMOVE_FACTOR));
    }

    /**
     * The kit rejects a gate that lets a factor authorise its own removal.
     *
     * @return void
     */
    public function testRejectsAGateThatLetsAFactorAuthorizeItsOwnRemoval(): void
    {
        $this->expectException(AssertionFailedError::class);

        FactorChangeGateContract::assertAFactorNeverAuthorizesItsOwnRemoval($this->allowingGate(), $this->removalSteppedUpOnlyWithTheFactor());
    }

    /**
     * The kit rejects a gate the configured requirement does not bind.
     *
     * @return void
     */
    public function testRejectsAGateTheConfiguredRequirementDoesNotBind(): void
    {
        $this->expectException(AssertionFailedError::class);

        FactorChangeGateContract::assertTheConfiguredRequirementBinds($this->allowingGate(), $this->changeBeyondTheConfiguredRequirement());
    }

    /**
     * The kit rejects a gate that gives a grant no end.
     *
     * @return void
     */
    public function testRejectsAGrantWithNoEnd(): void
    {
        $this->expectException(AssertionFailedError::class);

        FactorChangeGateContract::assertAFreshChangeIsAllowed(new ScriptedFactorChangeGate, $this->freshChange(FactorChange::ADD_FACTOR));
    }

    /**
     * The kit rejects a gate that gives a grant an end already past.
     *
     * @return void
     */
    public function testRejectsAGrantThatHasEnded(): void
    {
        $gate = new ScriptedFactorChangeGate(CarbonImmutable::now()->subSecond());

        $this->expectException(AssertionFailedError::class);

        FactorChangeGateContract::assertAFreshChangeIsAllowed($gate, $this->freshChange(FactorChange::ADD_FIRST_ADDITIONAL_FACTOR));
    }

    /**
     * A change that is not a grant needs no end.
     *
     * @return void
     */
    public function testAChangeThatIsNoGrantNeedsNoEnd(): void
    {
        FactorChangeGateContract::assertAFreshChangeIsAllowed(new ScriptedFactorChangeGate, $this->freshChange(FactorChange::GENERATE_RECOVERY_CODES));

        $this->addToAssertionCount(1);
    }

    /**
     * The bound default.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\FactorChangeGate
     */
    #[\Override]
    protected function factorChangeGate(): FactorChangeGate
    {
        return $this->container()->make(FactorChangeGate::class);
    }

    /**
     * A person who stepped up just now with a TOTP code, after a password, and
     * proved the password again just now.
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
     * A person who signed in two hours ago with a password, and proved nothing
     * since.
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
     * A person who stepped up just now only with the factor they remove,
     * holding another confirmed factor.
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
     * A person who stepped up just now with a TOTP code, asked for a change the
     * application configures to need AAL3.
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
     * A gate that allows every change, for a minute.
     *
     * @return \Tests\Fixtures\Requirements\ScriptedFactorChangeGate
     */
    private function allowingGate(): ScriptedFactorChangeGate
    {
        return new ScriptedFactorChangeGate(CarbonImmutable::now()->addMinute());
    }
}
