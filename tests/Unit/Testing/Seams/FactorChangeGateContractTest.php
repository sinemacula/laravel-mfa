<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing\Seams;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Collection;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\FactorChangeGate;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Contracts\Reauthenticator;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Enums\FactorChange;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Requirements\ConfiguredFactorChangeGate;
use SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Testing\Seams\Concerns\FactorChangeGateTests;
use SineMacula\Laravel\Mfa\Testing\Seams\FactorChangeGateContract;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Requirements\ScriptedFactorChangeGate;
use Tests\Fixtures\Requirements\SignInProofs;
use Tests\Fixtures\Seams\FreshReauthenticator;
use Tests\TestCase;

/**
 * The `FactorChangeGate` contract kit proves the default, which judges each
 * change on the session's recorded proofs, and rejects gates that allow what
 * they must refuse, refuse what they must allow, or refuse by returning.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FactorChangeGateContract::class)]
#[CoversClass(ConfiguredFactorChangeGate::class)]
final class FactorChangeGateContractTest extends TestCase
{
    use FactorChangeGateTests;

    /** @var string The id of the factor the person's step-up was made with. */
    private const string STEPPED_UP_WITH = 'factor-totp';

    /** @var string The id of the person's other confirmed factor. */
    private const string OTHER_FACTOR = 'factor-other';

    /**
     * The kit rejects a gate that allows a change from a stale session.
     *
     * @return void
     */
    public function testRejectsAGateThatAllowsAStaleChange(): void
    {
        $this->expectException(AssertionFailedError::class);

        FactorChangeGateContract::assertAStaleChangeIsRefused(new ScriptedFactorChangeGate(CarbonImmutable::now()->addMinute()), $this->staleChange(FactorChange::ADD_FACTOR));
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
        $this->expectException(AssertionFailedError::class);

        $gate = new ScriptedFactorChangeGate(CarbonImmutable::now()->subSecond());

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
     * The default refuses as the package, with `not_fresh`, and the grants it
     * makes end when their freshness does.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheDefaultsRefusalsAndGrants(): void
    {
        CarbonImmutable::setTestNow(CarbonImmutable::now()->startOfSecond());

        try {
            $this->factorChangeGate()->authorize($this->staleChange(FactorChange::ADD_FACTOR));
            self::fail('A stale change was expected to be refused.');
        } catch (OperationRefusedException $exception) {
            self::assertSame(FailureReason::NOT_FRESH, $exception->reason);
            self::assertTrue($exception->byPackage);
        }

        self::assertEquals(CarbonImmutable::now()->addSeconds(900), $this->factorChangeGate()->authorize($this->freshChange(FactorChange::ADD_FACTOR)));
        self::assertEquals(
            CarbonImmutable::now()->addSeconds(ConfiguredFactorChangeGate::REAUTHENTICATION_MAX_AGE),
            $this->factorChangeGate()->authorize($this->freshChange(FactorChange::ADD_FIRST_ADDITIONAL_FACTOR)),
        );
        self::assertNull($this->factorChangeGate()->authorize($this->freshChange(FactorChange::REMOVE_FACTOR)));
        self::assertNull($this->factorChangeGate()->authorize($this->freshChange(FactorChange::GENERATE_RECOVERY_CODES)));

        CarbonImmutable::setTestNow();
    }

    /**
     * The default lets the factor the step-up was made with authorise its own
     * removal while it is the person's only confirmed factor.
     *
     * @return void
     */
    public function testTheDefaultLetsTheLastFactorAuthorizeItsOwnRemoval(): void
    {
        $request = $this->removalSteppedUpOnlyWithTheFactor();
        $alone   = new FactorChangeRequest($request->identity, $request->application, $request->session, $request->change, new Collection, $request->factorId);

        self::assertNull($this->factorChangeGate()->authorize($alone));
    }

    /**
     * The default does not prove a first factor again on another sign-in.
     *
     * @return void
     */
    public function testTheDefaultRefusesAReauthenticationOfAnotherSignIn(): void
    {
        $request = $this->freshChange(FactorChange::ADD_FIRST_ADDITIONAL_FACTOR);
        $other   = new FactorChangeRequest($request->identity, $request->application, 'another-sign-in', $request->change, $request->factors);

        FactorChangeGateContract::assertAStaleChangeIsRefused($this->factorChangeGate(), $other);
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
        $user  = $this->signIn(static fn (SignInProofs $signIn): array => [$signIn->password(), $signIn->totp()]);
        $store = $this->container()->make(ProofStore::class);

        $this->container()->instance(Reauthenticator::class, new FreshReauthenticator($store));

        return $this->request($user, $change, $change->namesFactor() ? self::OTHER_FACTOR : null);
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
        $user = $this->signIn(static fn (SignInProofs $signIn): array => [$signIn->password(7200)]);

        $this->container()->forgetInstance(Reauthenticator::class);

        return $this->request($user, $change, $change->namesFactor() ? self::OTHER_FACTOR : null);
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
        $user = $this->signIn(static fn (SignInProofs $signIn): array => [$signIn->password(), $signIn->totp()]);

        return $this->request($user, FactorChange::REMOVE_FACTOR, self::STEPPED_UP_WITH);
    }

    /**
     * A person who stepped up just now with a TOTP code, asked for a change the
     * application configures to need a phishing-resistant proof.
     *
     * @return \SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest
     */
    #[\Override]
    protected function changeBeyondTheConfiguredRequirement(): FactorChangeRequest
    {
        $user = $this->signIn(static fn (SignInProofs $signIn): array => [$signIn->password(), $signIn->totp()]);

        return $this->request($user, FactorChange::ADD_FACTOR, null, Requirement::none()->withMinimumLevel(AssuranceLevel::AAL3, 300));
    }

    /**
     * The request for the person's change, holding two confirmed factors.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @param  \SineMacula\Laravel\Mfa\Enums\FactorChange  $change
     * @param  ?string  $factorId
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @return \SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest
     */
    private function request(TestUser $user, FactorChange $change, ?string $factorId, ?Requirement $requirement = null): FactorChangeRequest
    {
        $factors = new Collection([self::confirmed(self::STEPPED_UP_WITH), self::confirmed(self::OTHER_FACTOR)]);

        return new FactorChangeRequest($user, SignInProofs::APPLICATION, SignInProofs::SESSION, $change, $factors, $factorId, $requirement);
    }

    /**
     * A confirmed factor with the id, unsaved.
     *
     * @param  string  $id
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private static function confirmed(string $id): Factor
    {
        return (new Factor)->forceFill(['id' => $id, 'status' => 'confirmed']);
    }

    /**
     * Sign the person in afresh, recording the proofs given.
     *
     * @param  \Closure(\Tests\Fixtures\Requirements\SignInProofs): list<\SineMacula\Laravel\Mfa\Proofs\Proof>  $proofs
     * @return \Tests\Fixtures\Identities\TestUser
     */
    private function signIn(\Closure $proofs): TestUser
    {
        /** @var \Tests\Fixtures\Identities\TestUser $user */
        $user = TestUser::query()->firstOrCreate(['email' => 'changing@example.test']);

        $this->actingAs($user);

        $store = $this->container()->make(ProofStore::class);

        $store->begin($user, SignInProofs::APPLICATION, SignInProofs::SESSION);

        foreach ($proofs(SignInProofs::of($user)) as $proof) {
            $store->record($proof);
        }

        return $user;
    }
}
