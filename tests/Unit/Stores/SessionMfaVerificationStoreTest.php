<?php

declare(strict_types = 1);

namespace Tests\Unit\Stores;

use Carbon\Carbon;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Contracts\MfaVerificationStore;
use SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException;
use SineMacula\Laravel\Mfa\Stores\SessionMfaVerificationStore;

/**
 * Unit tests for the `SessionMfaVerificationStore` default store.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class SessionMfaVerificationStoreTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        Carbon::setTestNow('2026-04-15T10:00:00+00:00');
    }

    protected function tearDown(): void
    {
        Carbon::setTestNow();

        parent::tearDown();
    }

    public function testImplementsMfaVerificationStoreContract(): void
    {
        self::assertInstanceOf(
            MfaVerificationStore::class,
            new SessionMfaVerificationStore($this->buildSession()),
        );
    }

    public function testMarkVerifiedWithoutTimestampStampsNow(): void
    {
        $session = $this->buildSession();
        $store   = new SessionMfaVerificationStore($session);

        $store->markVerified($this->buildIdentity('user-1'));

        $expected = Carbon::now()->getTimestamp();
        self::assertSame($expected, $session->get('mfa.verified_at.user-1'));
    }

    public function testMarkVerifiedWithExplicitTimestampStampsGivenTimestamp(): void
    {
        $session = $this->buildSession();
        $store   = new SessionMfaVerificationStore($session);
        $at      = Carbon::parse('2026-04-14T08:30:00+00:00');

        $store->markVerified($this->buildIdentity(42), $at);

        self::assertSame($at->getTimestamp(), $session->get('mfa.verified_at.42'));
    }

    public function testMarkVerifiedThrowsWhenIdentifierIsNotScalar(): void
    {
        $store = new SessionMfaVerificationStore($this->buildSession());

        $this->expectException(UnsupportedIdentifierException::class);
        $this->expectExceptionMessage('SessionMfaVerificationStore requires a string or int');

        $store->markVerified($this->buildIdentity(new \stdClass));
    }

    public function testLastVerifiedAtReturnsNullWhenNoPriorVerification(): void
    {
        $store = new SessionMfaVerificationStore($this->buildSession());

        self::assertNull($store->lastVerifiedAt($this->buildIdentity('user-1')));
    }

    public function testLastVerifiedAtReturnsCarbonAfterMarkVerified(): void
    {
        $session = $this->buildSession();
        $store   = new SessionMfaVerificationStore($session);

        $store->markVerified($this->buildIdentity('user-1'));

        $result = $store->lastVerifiedAt($this->buildIdentity('user-1'));

        self::assertNotNull($result);
        self::assertSame(Carbon::now()->getTimestamp(), $result->getTimestamp());
    }

    public function testLastVerifiedAtReturnsNullWhenStoredValueIsNotInt(): void
    {
        $session = $this->buildSession();
        $session->put('mfa.verified_at.user-1', 'not-an-int');

        $store = new SessionMfaVerificationStore($session);

        self::assertNull($store->lastVerifiedAt($this->buildIdentity('user-1')));
    }

    public function testForgetClearsStoredKey(): void
    {
        $session = $this->buildSession();
        $store   = new SessionMfaVerificationStore($session);

        $store->markVerified($this->buildIdentity('user-1'));
        $store->forget($this->buildIdentity('user-1'));

        self::assertFalse($session->has('mfa.verified_at.user-1'));
        self::assertNull($store->lastVerifiedAt($this->buildIdentity('user-1')));
    }

    public function testKeysAreScopedPerIdentity(): void
    {
        $session = $this->buildSession();
        $store   = new SessionMfaVerificationStore($session);

        $alice = $this->buildIdentity('alice');
        $bob   = $this->buildIdentity('bob');

        Carbon::setTestNow('2026-04-15T09:00:00+00:00');
        $store->markVerified($alice);

        Carbon::setTestNow('2026-04-15T10:00:00+00:00');
        $store->markVerified($bob);

        $aliceAt = $store->lastVerifiedAt($alice);
        $bobAt   = $store->lastVerifiedAt($bob);

        self::assertNotNull($aliceAt);
        self::assertNotNull($bobAt);
        self::assertNotSame($aliceAt->getTimestamp(), $bobAt->getTimestamp());

        $store->forget($alice);

        self::assertNull($store->lastVerifiedAt($alice));
        self::assertNotNull($store->lastVerifiedAt($bob));
    }

    public function testLastVerifiedAtThrowsWhenIdentifierIsNotScalar(): void
    {
        $store = new SessionMfaVerificationStore($this->buildSession());

        $this->expectException(UnsupportedIdentifierException::class);

        $store->lastVerifiedAt($this->buildIdentity(new \stdClass));
    }

    public function testForgetThrowsWhenIdentifierIsNotScalar(): void
    {
        $store = new SessionMfaVerificationStore($this->buildSession());

        $this->expectException(UnsupportedIdentifierException::class);

        $store->forget($this->buildIdentity(new \stdClass));
    }

    /**
     * Build a real Laravel session store backed by an in-memory handler.
     *
     * @return \Illuminate\Session\Store
     */
    private function buildSession(): Store
    {
        $store = new Store('mfa-tests', new ArraySessionHandler(120));

        $store->start();

        return $store;
    }

    /**
     * Build a minimal authenticatable fake with the given identifier.
     *
     * @param  mixed  $identifier
     * @return \Illuminate\Contracts\Auth\Authenticatable
     */
    private function buildIdentity(mixed $identifier): Authenticatable
    {
        $identity = self::createStub(Authenticatable::class);
        $identity->method('getAuthIdentifier')->willReturn($identifier);

        return $identity;
    }
}
