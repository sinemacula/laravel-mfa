<?php

declare(strict_types = 1);

namespace Tests\Unit\Traits;

use Carbon\Carbon;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use Illuminate\Foundation\Testing\RefreshDatabase;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\TestUser;
use Tests\TestCase;

/**
 * Unit tests for the `ActsAsFactor` trait via the shipped `Factor` model.
 *
 * The trait implements the full `EloquentFactor` contract — 32 public
 * methods spanning column-name accessors, attribute readers, lockout
 * state, code lifecycle, and persistence. Every public surface has a
 * paired test (and most readers have separate "value present" /
 * "value absent" cases), so the class size is intrinsic to the
 * contract's surface area, not a sign of conflated subjects. The
 * `php:S1448` suppression below documents that judgment in code so
 * the next quality-gate refresh does not re-flag it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 *
 * @SuppressWarnings("php:S1448")
 */
final class ActsAsFactorTest extends TestCase
{
    use RefreshDatabase;

    /** @var string */
    private const string TEST_USER_EMAIL = 'alice@example.com';

    /** @var string */
    private const string SAMPLE_CODE = '123456';

    /**
     * Set up the test fixtures.
     *
     * @return void
     */
    protected function setUp(): void
    {
        parent::setUp();

        Carbon::setTestNow('2026-04-15T10:00:00+00:00');
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
     * Test authenticatable returns morph to.
     *
     * @return void
     */
    public function testAuthenticatableReturnsMorphTo(): void
    {
        self::assertInstanceOf(MorphTo::class, (new Factor)->authenticatable());
    }

    /**
     * Test driver column name accessor.
     *
     * @return void
     */
    public function testGetDriverNameReturnsDriverColumn(): void
    {
        self::assertSame('driver', (new Factor)->getDriverName());
    }

    /**
     * Test label column name accessor.
     *
     * @return void
     */
    public function testGetLabelNameReturnsLabelColumn(): void
    {
        self::assertSame('label', (new Factor)->getLabelName());
    }

    /**
     * Test recipient column name accessor.
     *
     * @return void
     */
    public function testGetRecipientNameReturnsRecipientColumn(): void
    {
        self::assertSame('recipient', (new Factor)->getRecipientName());
    }

    /**
     * Test secret column name accessor.
     *
     * @return void
     */
    public function testGetSecretNameReturnsSecretColumn(): void
    {
        self::assertSame('secret', (new Factor)->getSecretName());
    }

    /**
     * Test code column name accessor.
     *
     * @return void
     */
    public function testGetCodeNameReturnsCodeColumn(): void
    {
        self::assertSame('code', (new Factor)->getCodeName());
    }

    /**
     * Test expires_at column name accessor.
     *
     * @return void
     */
    public function testGetExpiresAtNameReturnsExpiresAtColumn(): void
    {
        self::assertSame('expires_at', (new Factor)->getExpiresAtName());
    }

    /**
     * Test attempts column name accessor.
     *
     * @return void
     */
    public function testGetAttemptsNameReturnsAttemptsColumn(): void
    {
        self::assertSame('attempts', (new Factor)->getAttemptsName());
    }

    /**
     * Test locked_until column name accessor.
     *
     * @return void
     */
    public function testGetLockedUntilNameReturnsLockedUntilColumn(): void
    {
        self::assertSame('locked_until', (new Factor)->getLockedUntilName());
    }

    /**
     * Test last_attempted_at column name accessor.
     *
     * @return void
     */
    public function testGetLastAttemptedAtNameReturnsLastAttemptedAtColumn(): void
    {
        self::assertSame('last_attempted_at', (new Factor)->getLastAttemptedAtName());
    }

    /**
     * Test verified_at column name accessor.
     *
     * @return void
     */
    public function testGetVerifiedAtNameReturnsVerifiedAtColumn(): void
    {
        self::assertSame('verified_at', (new Factor)->getVerifiedAtName());
    }

    /**
     * Test get factor identifier returns model key.
     *
     * @return void
     */
    public function testGetFactorIdentifierReturnsModelKey(): void
    {
        $factor     = new Factor;
        $factor->id = '01ABC';

        self::assertSame('01ABC', $factor->getFactorIdentifier());
    }

    /**
     * Test get driver returns string value.
     *
     * @return void
     */
    public function testGetDriverReturnsStringValue(): void
    {
        $factor = new Factor(['driver' => 'totp']);

        self::assertSame('totp', $factor->getDriver());
    }

    /**
     * Test get driver returns empty string when unset.
     *
     * @return void
     */
    public function testGetDriverReturnsEmptyStringWhenUnset(): void
    {
        self::assertSame('', (new Factor)->getDriver());
    }

    /**
     * Test get label returns string value.
     *
     * @return void
     */
    public function testGetLabelReturnsStringValue(): void
    {
        $factor = new Factor(['label' => 'Authenticator']);

        self::assertSame('Authenticator', $factor->getLabel());
    }

    /**
     * Test get label returns null when unset.
     *
     * @return void
     */
    public function testGetLabelReturnsNullWhenUnset(): void
    {
        self::assertNull((new Factor)->getLabel());
    }

    /**
     * Test get recipient returns string value.
     *
     * @return void
     */
    public function testGetRecipientReturnsStringValue(): void
    {
        $factor = new Factor(['recipient' => 'user@example.com']);

        self::assertSame('user@example.com', $factor->getRecipient());
    }

    /**
     * Test get recipient returns null when unset.
     *
     * @return void
     */
    public function testGetRecipientReturnsNullWhenUnset(): void
    {
        self::assertNull((new Factor)->getRecipient());
    }

    /**
     * Test get secret returns string value.
     *
     * @return void
     */
    public function testGetSecretReturnsStringValue(): void
    {
        $factor = new Factor(['secret' => 'plaintext']);

        self::assertSame('plaintext', $factor->getSecret());
    }

    /**
     * Test get secret returns null when unset.
     *
     * @return void
     */
    public function testGetSecretReturnsNullWhenUnset(): void
    {
        self::assertNull((new Factor)->getSecret());
    }

    /**
     * Test get code returns string value.
     *
     * @return void
     */
    public function testGetCodeReturnsStringValue(): void
    {
        $factor = new Factor(['code' => self::SAMPLE_CODE]);

        self::assertSame(self::SAMPLE_CODE, $factor->getCode());
    }

    /**
     * Test get code returns null when unset.
     *
     * @return void
     */
    public function testGetCodeReturnsNullWhenUnset(): void
    {
        self::assertNull((new Factor)->getCode());
    }

    /**
     * Test get expires at returns carbon when set.
     *
     * @return void
     */
    public function testGetExpiresAtReturnsCarbonWhenSet(): void
    {
        $at     = Carbon::now()->addMinutes(5);
        $factor = new Factor(['expires_at' => $at]);

        self::assertNotNull($factor->getExpiresAt());
        self::assertSame($at->getTimestamp(), $factor->getExpiresAt()->getTimestamp());
    }

    /**
     * Test get expires at returns null when unset.
     *
     * @return void
     */
    public function testGetExpiresAtReturnsNullWhenUnset(): void
    {
        self::assertNull((new Factor)->getExpiresAt());
    }

    /**
     * Test get attempts returns int.
     *
     * @return void
     */
    public function testGetAttemptsReturnsInt(): void
    {
        $factor = new Factor(['attempts' => 3]);

        self::assertSame(3, $factor->getAttempts());
    }

    /**
     * Test get attempts returns zero when unset.
     *
     * @return void
     */
    public function testGetAttemptsReturnsZeroWhenUnset(): void
    {
        self::assertSame(0, (new Factor)->getAttempts());
    }

    /**
     * Test get locked until returns carbon when set.
     *
     * @return void
     */
    public function testGetLockedUntilReturnsCarbonWhenSet(): void
    {
        $at     = Carbon::now()->addMinutes(15);
        $factor = new Factor(['locked_until' => $at]);

        self::assertNotNull($factor->getLockedUntil());
        self::assertSame($at->getTimestamp(), $factor->getLockedUntil()->getTimestamp());
    }

    /**
     * Test get locked until returns null when unset.
     *
     * @return void
     */
    public function testGetLockedUntilReturnsNullWhenUnset(): void
    {
        self::assertNull((new Factor)->getLockedUntil());
    }

    /**
     * Test is locked is false when not set.
     *
     * @return void
     */
    public function testIsLockedIsFalseWhenNotSet(): void
    {
        self::assertFalse((new Factor)->isLocked());
    }

    /**
     * Test is locked is false when lockout is in the past.
     *
     * @return void
     */
    public function testIsLockedIsFalseWhenLockoutIsInThePast(): void
    {
        $factor = new Factor(['locked_until' => Carbon::now()->subMinutes(5)]);

        self::assertFalse($factor->isLocked());
    }

    /**
     * Test is locked is true when lockout is in the future.
     *
     * @return void
     */
    public function testIsLockedIsTrueWhenLockoutIsInTheFuture(): void
    {
        $factor = new Factor(['locked_until' => Carbon::now()->addMinutes(5)]);

        self::assertTrue($factor->isLocked());
    }

    /**
     * Test get last attempted at returns carbon when set.
     *
     * @return void
     */
    public function testGetLastAttemptedAtReturnsCarbonWhenSet(): void
    {
        $at     = Carbon::now();
        $factor = new Factor(['last_attempted_at' => $at]);

        self::assertNotNull($factor->getLastAttemptedAt());
        self::assertSame($at->getTimestamp(), $factor->getLastAttemptedAt()->getTimestamp());
    }

    /**
     * Test get last attempted at returns null when unset.
     *
     * @return void
     */
    public function testGetLastAttemptedAtReturnsNullWhenUnset(): void
    {
        self::assertNull((new Factor)->getLastAttemptedAt());
    }

    /**
     * Test get verified at returns carbon when set.
     *
     * @return void
     */
    public function testGetVerifiedAtReturnsCarbonWhenSet(): void
    {
        $at     = Carbon::now();
        $factor = new Factor(['verified_at' => $at]);

        self::assertNotNull($factor->getVerifiedAt());
        self::assertSame($at->getTimestamp(), $factor->getVerifiedAt()->getTimestamp());
    }

    /**
     * Test get verified at returns null when unset.
     *
     * @return void
     */
    public function testGetVerifiedAtReturnsNullWhenUnset(): void
    {
        self::assertNull((new Factor)->getVerifiedAt());
    }

    /**
     * Test is verified is false when verified_at is absent.
     *
     * @return void
     */
    public function testIsVerifiedIsFalseWhenVerifiedAtIsAbsent(): void
    {
        self::assertFalse((new Factor)->isVerified());
    }

    /**
     * Test is verified is true when verified_at is present.
     *
     * @return void
     */
    public function testIsVerifiedIsTrueWhenVerifiedAtIsPresent(): void
    {
        $factor = new Factor(['verified_at' => Carbon::now()]);

        self::assertTrue($factor->isVerified());
    }

    /**
     * Test get authenticatable returns null when relation not loaded.
     *
     * @return void
     */
    public function testGetAuthenticatableReturnsNullWhenRelationNotLoaded(): void
    {
        $user = TestUser::create(['email' => self::TEST_USER_EMAIL, 'mfa_enabled' => true]);

        $factor = new Factor([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => $this->authenticatableId($user),
            'driver'               => 'totp',
        ]);
        $factor->save();

        // Fresh fetch (no eager load) → relation not loaded → null.
        /** @var \SineMacula\Laravel\Mfa\Models\Factor $fresh */
        $fresh = Factor::query()->findOrFail($factor->id);

        self::assertFalse($fresh->relationLoaded('authenticatable'));
        self::assertNull($fresh->getAuthenticatable());
    }

    /**
     * Test get authenticatable returns related model when loaded.
     *
     * @return void
     */
    public function testGetAuthenticatableReturnsRelatedModelWhenLoaded(): void
    {
        $user = TestUser::create(['email' => self::TEST_USER_EMAIL, 'mfa_enabled' => true]);

        $factor = new Factor([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => $this->authenticatableId($user),
            'driver'               => 'totp',
        ]);
        $factor->save();

        /** @var \SineMacula\Laravel\Mfa\Models\Factor $loaded */
        $loaded = Factor::query()->with('authenticatable')->findOrFail($factor->id);

        self::assertTrue($loaded->relationLoaded('authenticatable'));

        $resolved = $loaded->getAuthenticatable();

        self::assertInstanceOf(TestUser::class, $resolved);
        self::assertSame($user->getKey(), $resolved->getKey());
    }

    /**
     * Test get authenticatable returns null when related is not authenticatable.
     *
     * @return void
     */
    public function testGetAuthenticatableReturnsNullWhenRelatedIsNotAuthenticatable(): void
    {
        $factor = new Factor;
        $factor->setRelation('authenticatable', null);

        self::assertNull($factor->getAuthenticatable());
    }

    /**
     * Test record attempt increments attempts and stamps last attempted at.
     *
     * @return void
     */
    public function testRecordAttemptIncrementsAttemptsAndStampsLastAttemptedAt(): void
    {
        $factor = new Factor(['attempts' => 2]);

        $factor->recordAttempt();

        self::assertSame(3, $factor->getAttempts());
        self::assertNotNull($factor->getLastAttemptedAt());
        self::assertSame(Carbon::now()->getTimestamp(), $factor->getLastAttemptedAt()->getTimestamp());
    }

    /**
     * Test record attempt uses provided timestamp.
     *
     * @return void
     */
    public function testRecordAttemptUsesProvidedTimestamp(): void
    {
        $factor = new Factor;
        $at     = Carbon::parse('2026-04-14T08:00:00+00:00');

        $factor->recordAttempt($at);

        self::assertNotNull($factor->getLastAttemptedAt());
        self::assertSame($at->getTimestamp(), $factor->getLastAttemptedAt()->getTimestamp());
    }

    /**
     * Test reset attempts zeroes counter and clears lockout.
     *
     * @return void
     */
    public function testResetAttemptsZeroesCounterAndClearsLockout(): void
    {
        $factor = new Factor([
            'attempts'     => 4,
            'locked_until' => Carbon::now()->addMinutes(10),
        ]);

        $factor->resetAttempts();

        self::assertSame(0, $factor->getAttempts());
        self::assertNull($factor->getLockedUntil());
    }

    /**
     * Test apply lockout stamps locked until.
     *
     * @return void
     */
    public function testApplyLockoutStampsLockedUntil(): void
    {
        $factor = new Factor;
        $until  = Carbon::now()->addMinutes(15);

        $factor->applyLockout($until);

        self::assertNotNull($factor->getLockedUntil());
        self::assertSame($until->getTimestamp(), $factor->getLockedUntil()->getTimestamp());
    }

    /**
     * Test record verification stamps the verified_at timestamp.
     *
     * @return void
     */
    public function testRecordVerificationStampsVerifiedAtTimestamp(): void
    {
        $factor = $this->makeFullyPopulatedFactor();

        $factor->recordVerification();

        self::assertNotNull($factor->getVerifiedAt());
        self::assertSame(Carbon::now()->getTimestamp(), $factor->getVerifiedAt()->getTimestamp());
    }

    /**
     * Test record verification resets the attempt counter to zero.
     *
     * @return void
     */
    public function testRecordVerificationResetsAttemptCounter(): void
    {
        $factor = $this->makeFullyPopulatedFactor();

        $factor->recordVerification();

        self::assertSame(0, $factor->getAttempts());
    }

    /**
     * Test record verification clears the lockout timestamp.
     *
     * @return void
     */
    public function testRecordVerificationClearsLockoutTimestamp(): void
    {
        $factor = $this->makeFullyPopulatedFactor();

        $factor->recordVerification();

        self::assertNull($factor->getLockedUntil());
    }

    /**
     * Test record verification clears the pending code.
     *
     * @return void
     */
    public function testRecordVerificationClearsPendingCode(): void
    {
        $factor = $this->makeFullyPopulatedFactor();

        $factor->recordVerification();

        self::assertNull($factor->getCode());
    }

    /**
     * Test record verification clears the code expiry.
     *
     * @return void
     */
    public function testRecordVerificationClearsCodeExpiry(): void
    {
        $factor = $this->makeFullyPopulatedFactor();

        $factor->recordVerification();

        self::assertNull($factor->getExpiresAt());
    }

    /**
     * Test record verification uses provided timestamp.
     *
     * @return void
     */
    public function testRecordVerificationUsesProvidedTimestamp(): void
    {
        $factor = new Factor;
        $at     = Carbon::parse('2026-04-14T08:00:00+00:00');

        $factor->recordVerification($at);

        self::assertNotNull($factor->getVerifiedAt());
        self::assertSame($at->getTimestamp(), $factor->getVerifiedAt()->getTimestamp());
    }

    /**
     * Test issue code persists code and expiry.
     *
     * @return void
     */
    public function testIssueCodePersistsCodeAndExpiry(): void
    {
        $factor    = new Factor;
        $expiresAt = Carbon::now()->addMinutes(10);

        $factor->issueCode('987654', $expiresAt);

        self::assertSame('987654', $factor->getCode());
        self::assertNotNull($factor->getExpiresAt());
        self::assertSame($expiresAt->getTimestamp(), $factor->getExpiresAt()->getTimestamp());
    }

    /**
     * Test consume code clears code and expiry.
     *
     * @return void
     */
    public function testConsumeCodeClearsCodeAndExpiry(): void
    {
        $factor = new Factor([
            'code'       => self::SAMPLE_CODE,
            'expires_at' => Carbon::now()->addMinutes(5),
        ]);

        $factor->consumeCode();

        self::assertNull($factor->getCode());
        self::assertNull($factor->getExpiresAt());
    }

    /**
     * Test persist saves to the database.
     *
     * @return void
     */
    public function testPersistSavesToTheDatabase(): void
    {
        $user = TestUser::create(['email' => self::TEST_USER_EMAIL, 'mfa_enabled' => true]);

        $factor = new Factor([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => $this->authenticatableId($user),
            'driver'               => 'totp',
        ]);

        $factor->persist();

        self::assertTrue($factor->exists);
        self::assertNotNull($factor->id);
        // @phpstan-ignore staticMethod.dynamicCall (query() is a magic instance method on Eloquent\Model — PHPStan treats it as static.)
        self::assertTrue(Factor::query()->whereKey($factor->id)->exists());
    }

    /**
     * Return the test user's key as a string for morph-to wiring.
     *
     * @param  \Tests\Fixtures\TestUser  $user
     * @return string
     */
    private function authenticatableId(TestUser $user): string
    {
        /** @var int $key */
        $key = $user->getKey();

        return (string) $key;
    }

    /**
     * Build a factor with attempts, lockout, code, and expiry populated.
     *
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function makeFullyPopulatedFactor(): Factor
    {
        return new Factor([
            'attempts'     => 2,
            'locked_until' => Carbon::now()->addMinutes(5),
            'code'         => self::SAMPLE_CODE,
            'expires_at'   => Carbon::now()->addMinutes(5),
        ]);
    }
}
