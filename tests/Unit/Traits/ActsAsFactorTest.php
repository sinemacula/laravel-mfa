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
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class ActsAsFactorTest extends TestCase
{
    use RefreshDatabase;

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

    public function testAuthenticatableReturnsMorphTo(): void
    {
        self::assertInstanceOf(MorphTo::class, (new Factor)->authenticatable());
    }

    public function testColumnNameAccessors(): void
    {
        $factor = new Factor;

        self::assertSame('driver', $factor->getDriverName());
        self::assertSame('label', $factor->getLabelName());
        self::assertSame('recipient', $factor->getRecipientName());
        self::assertSame('secret', $factor->getSecretName());
        self::assertSame('code', $factor->getCodeName());
        self::assertSame('expires_at', $factor->getExpiresAtName());
        self::assertSame('attempts', $factor->getAttemptsName());
        self::assertSame('locked_until', $factor->getLockedUntilName());
        self::assertSame('last_attempted_at', $factor->getLastAttemptedAtName());
        self::assertSame('verified_at', $factor->getVerifiedAtName());
    }

    public function testGetFactorIdentifierReturnsModelKey(): void
    {
        $factor     = new Factor;
        $factor->id = '01ABC';

        self::assertSame('01ABC', $factor->getFactorIdentifier());
    }

    public function testGetDriverReturnsStringValue(): void
    {
        $factor = new Factor(['driver' => 'totp']);

        self::assertSame('totp', $factor->getDriver());
    }

    public function testGetDriverReturnsEmptyStringWhenUnset(): void
    {
        self::assertSame('', (new Factor)->getDriver());
    }

    public function testGetLabelReturnsStringValue(): void
    {
        $factor = new Factor(['label' => 'Authenticator']);

        self::assertSame('Authenticator', $factor->getLabel());
    }

    public function testGetLabelReturnsNullWhenUnset(): void
    {
        self::assertNull((new Factor)->getLabel());
    }

    public function testGetRecipientReturnsStringValue(): void
    {
        $factor = new Factor(['recipient' => 'user@example.com']);

        self::assertSame('user@example.com', $factor->getRecipient());
    }

    public function testGetRecipientReturnsNullWhenUnset(): void
    {
        self::assertNull((new Factor)->getRecipient());
    }

    public function testGetSecretReturnsStringValue(): void
    {
        $factor = new Factor(['secret' => 'plaintext']);

        self::assertSame('plaintext', $factor->getSecret());
    }

    public function testGetSecretReturnsNullWhenUnset(): void
    {
        self::assertNull((new Factor)->getSecret());
    }

    public function testGetCodeReturnsStringValue(): void
    {
        $factor = new Factor(['code' => '123456']);

        self::assertSame('123456', $factor->getCode());
    }

    public function testGetCodeReturnsNullWhenUnset(): void
    {
        self::assertNull((new Factor)->getCode());
    }

    public function testGetExpiresAtReturnsCarbonWhenSet(): void
    {
        $at     = Carbon::now()->addMinutes(5);
        $factor = new Factor(['expires_at' => $at]);

        self::assertNotNull($factor->getExpiresAt());
        self::assertSame($at->getTimestamp(), $factor->getExpiresAt()->getTimestamp());
    }

    public function testGetExpiresAtReturnsNullWhenUnset(): void
    {
        self::assertNull((new Factor)->getExpiresAt());
    }

    public function testGetAttemptsReturnsInt(): void
    {
        $factor = new Factor(['attempts' => 3]);

        self::assertSame(3, $factor->getAttempts());
    }

    public function testGetAttemptsReturnsZeroWhenUnset(): void
    {
        self::assertSame(0, (new Factor)->getAttempts());
    }

    public function testGetLockedUntilReturnsCarbonWhenSet(): void
    {
        $at     = Carbon::now()->addMinutes(15);
        $factor = new Factor(['locked_until' => $at]);

        self::assertNotNull($factor->getLockedUntil());
        self::assertSame($at->getTimestamp(), $factor->getLockedUntil()->getTimestamp());
    }

    public function testGetLockedUntilReturnsNullWhenUnset(): void
    {
        self::assertNull((new Factor)->getLockedUntil());
    }

    public function testIsLockedIsFalseWhenNotSet(): void
    {
        self::assertFalse((new Factor)->isLocked());
    }

    public function testIsLockedIsFalseWhenLockoutIsInThePast(): void
    {
        $factor = new Factor(['locked_until' => Carbon::now()->subMinutes(5)]);

        self::assertFalse($factor->isLocked());
    }

    public function testIsLockedIsTrueWhenLockoutIsInTheFuture(): void
    {
        $factor = new Factor(['locked_until' => Carbon::now()->addMinutes(5)]);

        self::assertTrue($factor->isLocked());
    }

    public function testGetLastAttemptedAtReturnsCarbonWhenSet(): void
    {
        $at     = Carbon::now();
        $factor = new Factor(['last_attempted_at' => $at]);

        self::assertNotNull($factor->getLastAttemptedAt());
        self::assertSame($at->getTimestamp(), $factor->getLastAttemptedAt()->getTimestamp());
    }

    public function testGetLastAttemptedAtReturnsNullWhenUnset(): void
    {
        self::assertNull((new Factor)->getLastAttemptedAt());
    }

    public function testGetVerifiedAtReturnsCarbonWhenSet(): void
    {
        $at     = Carbon::now();
        $factor = new Factor(['verified_at' => $at]);

        self::assertNotNull($factor->getVerifiedAt());
        self::assertSame($at->getTimestamp(), $factor->getVerifiedAt()->getTimestamp());
    }

    public function testGetVerifiedAtReturnsNullWhenUnset(): void
    {
        self::assertNull((new Factor)->getVerifiedAt());
    }

    public function testIsVerifiedReflectsVerifiedAtPresence(): void
    {
        $unverified = new Factor;
        $verified   = new Factor(['verified_at' => Carbon::now()]);

        self::assertFalse($unverified->isVerified());
        self::assertTrue($verified->isVerified());
    }

    public function testGetAuthenticatableReturnsNullWhenRelationNotLoaded(): void
    {
        $user = TestUser::create(['email' => 'alice@example.com', 'mfa_enabled' => true]);

        $factor = new Factor([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->getKey(),
            'driver'               => 'totp',
        ]);
        $factor->save();

        // Fresh fetch (no eager load) → relation not loaded → null.
        /** @var \SineMacula\Laravel\Mfa\Models\Factor $fresh */
        $fresh = Factor::query()->findOrFail($factor->id);

        self::assertFalse($fresh->relationLoaded('authenticatable'));
        self::assertNull($fresh->getAuthenticatable());
    }

    public function testGetAuthenticatableReturnsRelatedModelWhenLoaded(): void
    {
        $user = TestUser::create(['email' => 'alice@example.com', 'mfa_enabled' => true]);

        $factor = new Factor([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->getKey(),
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

    public function testGetAuthenticatableReturnsNullWhenRelatedIsNotAuthenticatable(): void
    {
        $factor = new Factor;
        $factor->setRelation('authenticatable', null);

        self::assertNull($factor->getAuthenticatable());
    }

    public function testRecordAttemptIncrementsAttemptsAndStampsLastAttemptedAt(): void
    {
        $factor = new Factor(['attempts' => 2]);

        $factor->recordAttempt();

        self::assertSame(3, $factor->getAttempts());
        self::assertNotNull($factor->getLastAttemptedAt());
        self::assertSame(Carbon::now()->getTimestamp(), $factor->getLastAttemptedAt()->getTimestamp());
    }

    public function testRecordAttemptUsesProvidedTimestamp(): void
    {
        $factor = new Factor;
        $at     = Carbon::parse('2026-04-14T08:00:00+00:00');

        $factor->recordAttempt($at);

        self::assertNotNull($factor->getLastAttemptedAt());
        self::assertSame($at->getTimestamp(), $factor->getLastAttemptedAt()->getTimestamp());
    }

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

    public function testApplyLockoutStampsLockedUntil(): void
    {
        $factor = new Factor;
        $until  = Carbon::now()->addMinutes(15);

        $factor->applyLockout($until);

        self::assertNotNull($factor->getLockedUntil());
        self::assertSame($until->getTimestamp(), $factor->getLockedUntil()->getTimestamp());
    }

    public function testRecordVerificationStampsVerifiedAtAndResetsState(): void
    {
        $factor = new Factor([
            'attempts'     => 2,
            'locked_until' => Carbon::now()->addMinutes(5),
            'code'         => '123456',
            'expires_at'   => Carbon::now()->addMinutes(5),
        ]);

        $factor->recordVerification();

        self::assertNotNull($factor->getVerifiedAt());
        self::assertSame(Carbon::now()->getTimestamp(), $factor->getVerifiedAt()->getTimestamp());
        self::assertSame(0, $factor->getAttempts());
        self::assertNull($factor->getLockedUntil());
        self::assertNull($factor->getCode());
        self::assertNull($factor->getExpiresAt());
    }

    public function testRecordVerificationUsesProvidedTimestamp(): void
    {
        $factor = new Factor;
        $at     = Carbon::parse('2026-04-14T08:00:00+00:00');

        $factor->recordVerification($at);

        self::assertNotNull($factor->getVerifiedAt());
        self::assertSame($at->getTimestamp(), $factor->getVerifiedAt()->getTimestamp());
    }

    public function testIssueCodePersistsCodeAndExpiry(): void
    {
        $factor    = new Factor;
        $expiresAt = Carbon::now()->addMinutes(10);

        $factor->issueCode('987654', $expiresAt);

        self::assertSame('987654', $factor->getCode());
        self::assertNotNull($factor->getExpiresAt());
        self::assertSame($expiresAt->getTimestamp(), $factor->getExpiresAt()->getTimestamp());
    }

    public function testConsumeCodeClearsCodeAndExpiry(): void
    {
        $factor = new Factor([
            'code'       => '123456',
            'expires_at' => Carbon::now()->addMinutes(5),
        ]);

        $factor->consumeCode();

        self::assertNull($factor->getCode());
        self::assertNull($factor->getExpiresAt());
    }

    public function testPersistSavesToTheDatabase(): void
    {
        $user = TestUser::create(['email' => 'alice@example.com', 'mfa_enabled' => true]);

        $factor = new Factor([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->getKey(),
            'driver'               => 'totp',
        ]);

        $factor->persist();

        self::assertTrue($factor->exists);
        self::assertNotNull($factor->id);
        self::assertTrue(Factor::query()->whereKey($factor->id)->exists());
    }
}
