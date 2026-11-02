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
 * spanning column-name accessors, attribute readers, verification state and
 * persistence. Every public surface has a paired test (and most readers have
 * separate "value present" / "value absent" cases), so the class size is
 * intrinsic to the contract's surface area, not a sign of conflated subjects.
 * The `php:S1448` suppression below documents that judgement in code so the
 * next quality-gate refresh does not re-flag it.
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
     * Test record verification stamps the last use.
     *
     * @return void
     */
    public function testRecordVerificationStampsLastUse(): void
    {
        $factor = $this->makeFullyPopulatedFactor();

        $factor->recordVerification();

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
     * Test record verification uses provided timestamp.
     *
     * @return void
     */
    public function testRecordVerificationUsesProvidedTimestamp(): void
    {
        $factor = new Factor;
        $at     = Carbon::parse('2026-04-14T08:00:00+00:00');

        $factor->recordVerification($at);

        self::assertNotNull($factor->getLastUsedAt());
        self::assertSame($at->getTimestamp(), $factor->getLastUsedAt()->getTimestamp());
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
     * Build a factor with failures in a row populated.
     *
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function makeFullyPopulatedFactor(): Factor
    {
        return new Factor([
            'consecutive_failures' => 2,
        ]);
    }
}
