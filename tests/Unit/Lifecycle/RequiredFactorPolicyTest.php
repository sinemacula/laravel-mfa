<?php

declare(strict_types = 1);

namespace Tests\Unit\Lifecycle;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Collection;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\IdentityRequirement;
use SineMacula\Laravel\Mfa\Lifecycle\RequiredFactorPolicy;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Models\PasskeyAssociation;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyAssociations;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use Tests\Fixtures\Factors\FactorSets;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Passkeys\Concerns\ArrangesPasskeys;
use Tests\TestCase;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RequiredFactorPolicy::class)]
#[CoversClass(PasskeyAssociations::class)]
final class RequiredFactorPolicyTest extends TestCase
{
    use ArrangesPasskeys;

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAnyFactorMayBeRemovedWhenNoneIsRequired(): void
    {
        $this->enablePasskeys();

        $user = $this->signedInPerson();

        self::assertTrue($this->policy()->allowsRemoval($user, self::APPLICATION, $this->confirmedFactor($user), $this->factorsOf($user)));
    }

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheLastAcceptableFactorStaysWhileAnApplicationRequiresOne(): void
    {
        $this->enablePasskeys(['types' => ['totp']]);

        config()->set('mfa.applications.admin', ['requirement' => 'always', 'first_factor' => ['method' => 'password', 'channel' => 'password']]);

        $user = $this->signedInPerson();
        $totp = $this->confirmedFactor($user);

        self::assertFalse($this->policy()->allowsRemoval($user, self::APPLICATION, $totp, $this->factorsOf($user)));

        $pending = $this->confirmedFactor($user);
        $pending->update(['status' => 'pending']);

        self::assertFalse($this->policy()->allowsRemoval($user, self::APPLICATION, $totp, $this->factorsOf($user)));

        $this->confirmedFactor($user, 'sms');

        self::assertFalse($this->policy()->allowsRemoval($user, self::APPLICATION, $totp, $this->factorsOf($user)));

        $this->confirmedFactor($user);

        self::assertTrue($this->policy()->allowsRemoval($user, self::APPLICATION, $totp, $this->factorsOf($user)));
    }

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheIdentitysOwnRequirementKeepsTheLastFactor(): void
    {
        $this->enablePasskeys();

        $user = $this->signedInPerson();
        $user->update(['mfa_enabled' => true]);

        self::assertFalse($this->policy()->allowsRemoval($user, self::APPLICATION, $this->confirmedFactor($user), $this->factorsOf($user)));
        self::assertSame(1, Factor::query()->count());
    }

    /**
     * A passkey counts only while its association matches it.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAnUnusablePasskeyDoesNotKeepTheIdentityCovered(): void
    {
        $this->enablePasskeys();

        $user = $this->signedInPerson();
        $user->update(['mfa_enabled' => true]);

        $totp    = $this->confirmedFactor($user);
        $passkey = $this->confirmedFactor($user, 'passkey', self::CREDENTIAL);

        self::assertTrue($this->policy()->allowsRemoval($user, self::APPLICATION, $totp, $this->factorsOf($user)));

        PasskeyAssociation::query()->where('factor_id', $passkey->id)->update(['credential_id' => self::OTHER_CREDENTIAL]);

        self::assertFalse($this->policy()->allowsRemoval($user, self::APPLICATION, $totp, $this->factorsOf($user)));

        PasskeyAssociation::query()->where('factor_id', $passkey->id)->update(['credential_id' => self::CREDENTIAL, 'authenticatable_id' => 'someone-else']);

        self::assertFalse($this->policy()->allowsRemoval($user, self::APPLICATION, $totp, $this->factorsOf($user)));

        PasskeyAssociation::query()->where('factor_id', $passkey->id)->delete();

        self::assertFalse($this->policy()->allowsRemoval($user, self::APPLICATION, $totp, $this->factorsOf($user)));
    }

    /**
     * The policy decides on the factors it is given.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testADisabledOrUnlistedFactorDoesNotKeepTheIdentityCovered(): void
    {
        $this->enablePasskeys();

        $user = $this->signedInPerson();
        $user->update(['mfa_enabled' => true]);

        $totp  = $this->confirmedFactor($user);
        $other = $this->confirmedFactor($user);

        self::assertTrue($this->policy()->allowsRemoval($user, self::APPLICATION, $totp, $this->factorsOf($user)));
        self::assertFalse($this->policy()->allowsRemoval($user, self::APPLICATION, $totp, FactorSets::of($totp)));

        $other->update(['disabled_at' => CarbonImmutable::now()]);

        self::assertFalse($this->policy()->allowsRemoval($user, self::APPLICATION, $totp, $this->factorsOf($user)));
    }

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheIdentitysPartIsAskedOfTheBoundSeam(): void
    {
        $this->enablePasskeys();

        $user = $this->signedInPerson();
        $totp = $this->confirmedFactor($user);

        $seam = \Mockery::mock(IdentityRequirement::class);
        $seam->shouldReceive('requirementFor')->with($user, self::APPLICATION)->andReturn(Requirement::none()->withAdditionalVerification());

        $this->container()->instance(IdentityRequirement::class, $seam);

        self::assertFalse($this->policy()->allowsRemoval($user, self::APPLICATION, $totp, $this->factorsOf($user)));

        \Mockery::close();
    }

    /**
     * As a caller hands them to the policy.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @return \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>
     */
    private function factorsOf(TestUser $user): Collection
    {
        return FactorSets::stored((string) $user->id);
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Lifecycle\RequiredFactorPolicy
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function policy(): RequiredFactorPolicy
    {
        return $this->container()->make(RequiredFactorPolicy::class);
    }
}
