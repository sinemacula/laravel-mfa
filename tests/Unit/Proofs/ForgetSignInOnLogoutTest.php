<?php

declare(strict_types = 1);

namespace Tests\Unit\Proofs;

use Illuminate\Auth\Events\Logout;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException;
use SineMacula\Laravel\Mfa\Proofs\ForgetSignInOnLogout;
use SineMacula\Laravel\Mfa\Proofs\SessionProofStore;
use Tests\Fixtures\Identities\NonScalarIdentifierUser;
use Tests\Fixtures\Identities\PlainUser;
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;

/**
 * Tests for `ForgetSignInOnLogout`: Laravel's `Logout` event forgets the
 * identity's sign-in, and leaves an identity that holds none alone.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ForgetSignInOnLogout::class)]
final class ForgetSignInOnLogoutTest extends TestCase
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
     * Signing out forgets the identity's sign-in.
     *
     * @return void
     */
    public function testForgetsTheSignIn(): void
    {
        $store = new SessionProofStore(new Store('test', new ArraySessionHandler(10)));
        $user  = new TestUser;

        $user->setAttribute('id', 7);

        $store->begin($user, 'sign-in-1');

        (new ForgetSignInOnLogout($store))(new Logout('web', $user));

        self::assertNull($store->currentSession($user));
    }

    /**
     * An identity that cannot hold factors forgets nothing.
     *
     * @return void
     */
    public function testLeavesAnIdentityThatCannotHoldFactorsAlone(): void
    {
        $store = \Mockery::mock(ProofStore::class);
        $store->shouldNotReceive('forget');

        (new ForgetSignInOnLogout($store))(new Logout('web', new PlainUser));

        $store->shouldNotHaveReceived('forget');
    }

    /**
     * An identity whose key cannot name a record signs out without failing.
     *
     * @return void
     */
    public function testLeavesAnIdentityWhoseKeyCannotNameARecordAlone(): void
    {
        $store = \Mockery::mock(ProofStore::class);
        $store->shouldReceive('forget')->once()->andThrow(new UnsupportedIdentifierException('Unsupported.'));

        (new ForgetSignInOnLogout($store))(new Logout('web', new NonScalarIdentifierUser));

        $store->shouldHaveReceived('forget')->once();
    }
}
