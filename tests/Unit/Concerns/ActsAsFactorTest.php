<?php

declare(strict_types = 1);

namespace Tests\Unit\Concerns;

use Carbon\Carbon;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use Illuminate\Foundation\Testing\RefreshDatabase;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Mfa\Concerns\ActsAsFactor;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;

/**
 * Unit tests for the `ActsAsFactor` trait via the shipped `Factor` model.
 *
 * The trait implements the full `EloquentFactor` contract, its public methods
 * spanning column-name accessors, attribute readers, verification state, code
 * lifecycle, and persistence. Every public surface has a paired test (and most
 * readers have separate "value present" / "value absent" cases), so the class
 * size is intrinsic to the contract's surface area, not a sign of conflated
 * subjects. The `php:S1448` suppression below documents that judgement in code
 * so the next quality-gate refresh does not re-flag it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1448")
 */
#[CoversTrait(ActsAsFactor::class)]
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
    #[\Override]
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
    #[\Override]
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
    public function testGetTypeNameReturnsTypeColumn(): void
    {
        self::assertSame('type', (new Factor)->getTypeName());
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
     * Test destination column name accessor.
     *
     * @return void
     */
    public function testGetDestinationNameReturnsDestinationColumn(): void
    {
        self::assertSame('destination', (new Factor)->getDestinationName());
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
    public function testGetTypeReturnsStringValue(): void
    {
        $factor = new Factor(['type' => 'totp']);

        self::assertSame('totp', $factor->getType());
    }

    /**
     * Test get driver returns empty string when unset.
     *
     * @return void
     */
    public function testGetTypeReturnsEmptyStringWhenUnset(): void
    {
        self::assertSame('', (new Factor)->getType());
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
     * Test get destination returns string value.
     *
     * @return void
     */
    public function testGetDestinationReturnsStringValue(): void
    {
        $factor = new Factor(['destination' => 'user@example.com']);

        self::assertSame('user@example.com', $factor->getDestination());
    }

    /**
     * Test get destination returns null when unset.
     *
     * @return void
     */
    public function testGetDestinationReturnsNullWhenUnset(): void
    {
        self::assertNull((new Factor)->getDestination());
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
            'type'                 => 'totp',
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
            'type'                 => 'totp',
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
     * Test get authenticatable returns null when related is not
     * authenticatable.
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
     * Test record verification stamps the verified_at timestamp, and the last
     * use with it.
     *
     * @return void
     */
    public function testRecordVerificationStampsVerifiedAtTimestamp(): void
    {
        $factor = $this->makeFullyPopulatedFactor();

        $factor->recordVerification();

        self::assertNotNull($factor->getVerifiedAt());
        self::assertSame(Carbon::now()->getTimestamp(), $factor->getVerifiedAt()->getTimestamp());
        self::assertSame(Carbon::now()->getTimestamp(), $factor->getLastUsedAt()?->getTimestamp());
    }

    /**
     * Test record verification leaves the failures in a row to the attempt
     * service, which resets them under the identity's lock.
     *
     * @return void
     */
    public function testRecordVerificationLeavesTheFailuresInARow(): void
    {
        $factor = $this->makeFullyPopulatedFactor();

        $factor->recordVerification();

        self::assertSame(2, $factor->getConsecutiveFailures());
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
            'type'                 => 'totp',
        ]);

        $factor->persist();

        self::assertTrue($factor->exists);
        self::assertNotNull($factor->id);
        // @phpstan-ignore staticMethod.dynamicCall
        self::assertTrue(Factor::query()->whereKey($factor->id)->exists());
    }

    /**
     * Return the test user's key as a string for morph-to wiring.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @return string
     */
    private function authenticatableId(TestUser $user): string
    {
        /** @var int $key */
        $key = $user->getKey();

        return (string) $key;
    }

    /**
     * Build a factor with failures in a row, code, and expiry populated.
     *
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function makeFullyPopulatedFactor(): Factor
    {
        return new Factor([
            'consecutive_failures' => 2,
            'code'                 => self::SAMPLE_CODE,
            'expires_at'           => Carbon::now()->addMinutes(5),
        ]);
    }
}
