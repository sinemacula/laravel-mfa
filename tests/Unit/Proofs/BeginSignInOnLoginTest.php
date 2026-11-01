<?php

declare(strict_types = 1);

namespace Tests\Unit\Proofs;

use Illuminate\Auth\Events\Login;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException;
use SineMacula\Laravel\Mfa\Proofs\BeginSignInOnLogin;
use SineMacula\Laravel\Mfa\Proofs\SessionProofStore;
use Tests\Fixtures\Identities\NonScalarIdentifierUser;
use Tests\Fixtures\Identities\PlainUser;
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;

/**
 * Tests for `BeginSignInOnLogin`: Laravel's `Login` event begins a new sign-in,
 * named by a fresh random id, for an identity that can hold factors, and
 * leaves every other identity alone.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(BeginSignInOnLogin::class)]
final class BeginSignInOnLoginTest extends TestCase
{
    /**
     * Tear down Mockery expectations between test cases.
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
     * Every sign-in begins under a fresh lowercase ULID.
     *
     * @return void
     */
    public function testBeginsASignInUnderAFreshId(): void
    {
        $store    = new SessionProofStore(new Store('test', new ArraySessionHandler(10)));
        $listener = new BeginSignInOnLogin($store);
        $user     = $this->user();

        $listener(new Login('web', $user, false));

        $first = $store->currentSession($user);

        $listener(new Login('web', $user, false));

        $second = $store->currentSession($user);

        self::assertIsString($first);
        self::assertIsString($second);
        self::assertMatchesRegularExpression('/^[0-9a-hjkmnp-tv-z]{26}$/', $first);
        self::assertNotSame($first, $second);
    }

    /**
     * An identity that cannot hold factors begins no sign-in.
     *
     * @return void
     */
    public function testLeavesAnIdentityThatCannotHoldFactorsAlone(): void
    {
        $store = \Mockery::mock(ProofStore::class);
        $store->shouldNotReceive('begin');

        (new BeginSignInOnLogin($store))(new Login('web', new PlainUser, false));

        $store->shouldNotHaveReceived('begin');
    }

    /**
     * An identity whose key cannot name a record signs in without a sign-in
     * of its own rather than failing.
     *
     * @return void
     */
    public function testLeavesAnIdentityWhoseKeyCannotNameARecordAlone(): void
    {
        $store = \Mockery::mock(ProofStore::class);
        $store->shouldReceive('begin')->once()->andThrow(new UnsupportedIdentifierException('Unsupported.'));

        (new BeginSignInOnLogin($store))(new Login('web', new NonScalarIdentifierUser, false));

        $store->shouldHaveReceived('begin')->once();
    }

    /**
     * A test user, never saved.
     *
     * @return \Tests\Fixtures\Identities\TestUser
     */
    private function user(): TestUser
    {
        $user = new TestUser;

        $user->setAttribute('id', 7);

        return $user;
    }
}
