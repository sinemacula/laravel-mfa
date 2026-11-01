<?php

declare(strict_types = 1);

namespace Tests\Unit\Requirements;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\MfaPolicy;
use SineMacula\Laravel\Mfa\Requirements\RequirementService;
use Tests\Fixtures\TestUser;
use Tests\TestCase;

/**
 * Tests for `RequirementService`: MFA applies to an identity that asks for it,
 * or that the bound policy enforces it on, and never to a guest.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RequirementService::class)]
final class RequirementServiceTest extends TestCase
{
    /**
     * Release the Mockery expectations.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        \Mockery::close();

        parent::tearDown();
    }

    /**
     * MFA never applies to a guest, and the policy is not asked.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testMfaDoesNotApplyToAGuest(): void
    {
        $this->policyAnswering(null);

        self::assertFalse($this->service()->shouldUse());
    }

    /**
     * MFA applies to an identity that asks for it, without asking the policy.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testMfaAppliesToAnIdentityThatAsksForIt(): void
    {
        $this->signIn(true);
        $this->policyAnswering(null);

        self::assertTrue($this->service()->shouldUse());
    }

    /**
     * For an identity that does not ask for it, MFA applies as the policy says.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testOtherwiseThePolicyDecides(): void
    {
        $user = $this->signIn(false);

        $this->policyAnswering(true, $user);
        self::assertTrue($this->service()->shouldUse());

        $this->policyAnswering(false, $user);
        self::assertFalse($this->service()->shouldUse());
    }

    /**
     * Resolve the requirement service.
     *
     * @return \SineMacula\Laravel\Mfa\Requirements\RequirementService
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function service(): RequirementService
    {
        return $this->container()->make(RequirementService::class);
    }

    /**
     * Bind a policy that answers the given decision for the identity, or that
     * must not be asked when the decision is null.
     *
     * @param  ?bool  $decision
     * @param  ?\Tests\Fixtures\TestUser  $identity
     * @return void
     */
    private function policyAnswering(?bool $decision, ?TestUser $identity = null): void
    {
        $policy = \Mockery::mock(MfaPolicy::class);

        if ($decision === null) {
            $policy->shouldNotReceive('shouldEnforce');
        } else {
            $policy->shouldReceive('shouldEnforce')->once()->with($identity)->andReturn($decision);
        }

        $this->container()->instance(MfaPolicy::class, $policy);
    }

    /**
     * Create a test user with the given preference and authenticate as them.
     *
     * @param  bool  $prefersMfa
     * @return \Tests\Fixtures\TestUser
     */
    private function signIn(bool $prefersMfa): TestUser
    {
        /** @var \Tests\Fixtures\TestUser $user */
        $user = TestUser::query()->create(['email' => 'requirement@example.com', 'mfa_enabled' => $prefersMfa]);

        $this->actingAs($user);

        return $user;
    }
}
