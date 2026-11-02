<?php

declare(strict_types = 1);

namespace Tests\Unit\Lifecycle;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Lifecycle\RequiredFactorPolicy;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\Passkeys\Concerns\ArrangesPasskeys;
use Tests\TestCase;

/**
 * Tests for `RequiredFactorPolicy`, the default last factor policy: while a
 * factor is required, the last one an application accepts may not be removed;
 * otherwise any may.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RequiredFactorPolicy::class)]
final class RequiredFactorPolicyTest extends TestCase
{
    use ArrangesPasskeys;

    /**
     * With no factor required, the only factor may be removed.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAnyFactorMayBeRemovedWhenNoneIsRequired(): void
    {
        $this->enablePasskeys();

        $user = $this->signedInPerson();

        self::assertTrue($this->policy()->allowsRemoval($user, self::APPLICATION, $this->confirmedFactor($user)));
    }

    /**
     * While an application always requires a factor, the last acceptable one
     * stays; another confirmed factor of an enabled type lets it go.
     *
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

        self::assertFalse($this->policy()->allowsRemoval($user, self::APPLICATION, $totp));

        $pending = $this->confirmedFactor($user);
        $pending->update(['status' => 'pending']);

        self::assertFalse($this->policy()->allowsRemoval($user, self::APPLICATION, $totp));

        $this->confirmedFactor($user, 'sms');

        self::assertFalse($this->policy()->allowsRemoval($user, self::APPLICATION, $totp));

        $this->confirmedFactor($user);

        self::assertTrue($this->policy()->allowsRemoval($user, self::APPLICATION, $totp));
    }

    /**
     * The identity's own requirement keeps its last acceptable factor too.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheIdentitysOwnRequirementKeepsTheLastFactor(): void
    {
        $this->enablePasskeys();

        $user = $this->signedInPerson();
        $user->update(['mfa_enabled' => true]);

        self::assertFalse($this->policy()->allowsRemoval($user, self::APPLICATION, $this->confirmedFactor($user)));
        self::assertSame(1, Factor::query()->count());
    }

    /**
     * The policy under test.
     *
     * @return \SineMacula\Laravel\Mfa\Lifecycle\RequiredFactorPolicy
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function policy(): RequiredFactorPolicy
    {
        return $this->container()->make(RequiredFactorPolicy::class);
    }
}
