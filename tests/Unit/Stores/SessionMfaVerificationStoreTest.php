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
use Tests\Fixtures\FirstStoreIdentity;
use Tests\Fixtures\SecondStoreIdentity;

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
    /** @var string Fixed "now" used throughout the suite. */
    private const string NOW = '2026-04-15T10:00:00+00:00';

    /** @var string Earlier "now" used when contrasting two verifications. */
    private const string EARLIER = '2026-04-15T09:00:00+00:00';

    /** @var string Identifier suffix reused by single-identity assertions. */
    private const string IDENTIFIER_SUFFIX = '.user-1';

    /**
     * Set up the test fixtures.
     *
     * @return void
     */
    protected function setUp(): void
    {
        parent::setUp();

        Carbon::setTestNow(self::NOW);
    }

    /**
     * Tear down the test fixtures.
     *
     * @return void
     */
    protected function tearDown(): void
    {
        Carbon::setTestNow();

        parent::tearDown();
    }

    /**
     * Test implements mfa verification store contract.
     *
     * @return void
     */
    public function testImplementsMfaVerificationStoreContract(): void
    {
        self::assertInstanceOf(
            MfaVerificationStore::class,
            new SessionMfaVerificationStore($this->buildSession()),
        );
    }

    /**
     * Test mark verified without timestamp stamps now.
     *
     * @return void
     */
    public function testMarkVerifiedWithoutTimestampStampsNow(): void
    {
        $session = $this->buildSession();
        $store   = new SessionMfaVerificationStore($session);

        $identity = $this->buildIdentity('user-1');
        $store->markVerified($identity);

        $expected = Carbon::now()->getTimestamp();
        self::assertSame(
            $expected,
            $session->get('mfa.verified_at.' . $identity::class . self::IDENTIFIER_SUFFIX),
        );
    }

    /**
     * Test mark verified with explicit timestamp stamps given timestamp.
     *
     * @return void
     */
    public function testMarkVerifiedWithExplicitTimestampStampsGivenTimestamp(): void
    {
        $session = $this->buildSession();
        $store   = new SessionMfaVerificationStore($session);
        $at      = Carbon::parse('2026-04-14T08:30:00+00:00');

        $identity = $this->buildIdentity(42);
        $store->markVerified($identity, $at);

        self::assertSame(
            $at->getTimestamp(),
            $session->get('mfa.verified_at.' . $identity::class . '.42'),
        );
    }

    /**
     * Test mark verified throws when identifier is not scalar.
     *
     * @return void
     */
    public function testMarkVerifiedThrowsWhenIdentifierIsNotScalar(): void
    {
        $store = new SessionMfaVerificationStore($this->buildSession());

        $this->expectException(UnsupportedIdentifierException::class);
        $this->expectExceptionMessage('SessionMfaVerificationStore requires a string or int');

        $store->markVerified($this->buildIdentity(new \stdClass));
    }

    /**
     * Test last verified at returns null when no prior verification.
     *
     * @return void
     */
    public function testLastVerifiedAtReturnsNullWhenNoPriorVerification(): void
    {
        $store = new SessionMfaVerificationStore($this->buildSession());

        self::assertNull($store->lastVerifiedAt($this->buildIdentity('user-1')));
    }

    /**
     * Test last verified at returns carbon after mark verified.
     *
     * @return void
     */
    public function testLastVerifiedAtReturnsCarbonAfterMarkVerified(): void
    {
        $session = $this->buildSession();
        $store   = new SessionMfaVerificationStore($session);

        $store->markVerified($this->buildIdentity('user-1'));

        $verifiedAt = $store->lastVerifiedAt($this->buildIdentity('user-1'));

        self::assertNotNull($verifiedAt);
        self::assertSame(Carbon::now()->getTimestamp(), $verifiedAt->getTimestamp());
    }

    /**
     * Test last verified at returns null when stored value is not int.
     *
     * @return void
     */
    public function testLastVerifiedAtReturnsNullWhenStoredValueIsNotInt(): void
    {
        $identity = $this->buildIdentity('user-1');
        $session  = $this->buildSession();
        $session->put(
            'mfa.verified_at.' . $identity::class . self::IDENTIFIER_SUFFIX,
            'not-an-int',
        );

        $store = new SessionMfaVerificationStore($session);

        self::assertNull($store->lastVerifiedAt($identity));
    }

    /**
     * Test forget clears stored key.
     *
     * @return void
     */
    public function testForgetClearsStoredKey(): void
    {
        $session  = $this->buildSession();
        $store    = new SessionMfaVerificationStore($session);
        $identity = $this->buildIdentity('user-1');

        $store->markVerified($identity);
        $store->forget($identity);

        self::assertFalse(
            $session->has('mfa.verified_at.' . $identity::class . self::IDENTIFIER_SUFFIX),
        );
        self::assertNull($store->lastVerifiedAt($identity));
    }

    /**
     * Test keys are scoped by identity class so two different
     * authenticatables sharing the same identifier do not collide on a single
     * verification slot.
     *
     * @return void
     */
    public function testKeysAreScopedByIdentityClass(): void
    {
        $session = $this->buildSession();
        $store   = new SessionMfaVerificationStore($session);

        $alpha = new FirstStoreIdentity('shared-7');
        $beta  = new SecondStoreIdentity('shared-7');

        Carbon::setTestNow(self::EARLIER);
        $store->markVerified($alpha);

        Carbon::setTestNow(self::NOW);
        $store->markVerified($beta);

        $alphaAt = $store->lastVerifiedAt($alpha);
        $betaAt  = $store->lastVerifiedAt($beta);

        self::assertNotNull($alphaAt);
        self::assertNotNull($betaAt);
        self::assertNotSame(
            $alphaAt->getTimestamp(),
            $betaAt->getTimestamp(),
            'Two identity classes sharing an identifier must not share MFA state.',
        );

        $store->forget($alpha);

        self::assertNull($store->lastVerifiedAt($alpha));
        self::assertNotNull($store->lastVerifiedAt($beta));
    }

    /**
     * Test keys are scoped per identity.
     *
     * @return void
     */
    public function testKeysAreScopedPerIdentity(): void
    {
        $session = $this->buildSession();
        $store   = new SessionMfaVerificationStore($session);

        $alice = $this->buildIdentity('alice');
        $bob   = $this->buildIdentity('bob');

        Carbon::setTestNow(self::EARLIER);
        $store->markVerified($alice);

        Carbon::setTestNow(self::NOW);
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

    /**
     * Test last verified at throws when identifier is not scalar.
     *
     * @return void
     */
    public function testLastVerifiedAtThrowsWhenIdentifierIsNotScalar(): void
    {
        $store = new SessionMfaVerificationStore($this->buildSession());

        $this->expectException(UnsupportedIdentifierException::class);

        $store->lastVerifiedAt($this->buildIdentity(new \stdClass));
    }

    /**
     * Test forget throws when identifier is not scalar.
     *
     * @return void
     */
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
