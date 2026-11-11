<?php

declare(strict_types = 1);

namespace Tests\Unit\Concerns;

use Carbon\Carbon;
use Carbon\CarbonImmutable;
use Carbon\Exceptions\InvalidFormatException;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use Illuminate\Foundation\Testing\RefreshDatabase;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Concerns\ActsAsFactor;
use SineMacula\Laravel\Mfa\Exceptions\InvalidModelException;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\Factors\RemappedLockoutFactor;
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;

/**
 * Size follows the `EloquentFactor` contract's surface, hence the `php:S1448`
 * suppression.
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
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Carbon::setTestNow('2026-04-15T10:00:00+00:00');
    }

    /**
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();

        parent::tearDown();
    }

    /**
     * Remapped columns included and with no cast declared; the model's other
     * casts are left alone.
     *
     * @return void
     */
    public function testTheTraitCastsTheColumnsARefusalReads(): void
    {
        $factor = new RemappedLockoutFactor;

        self::assertSame('datetime', $factor->getCasts()['held_until']);
        self::assertSame('datetime', $factor->getCasts()['disabled_at']);
        self::assertSame('integer', $factor->getCasts()['consecutive_failures']);
        self::assertArrayNotHasKey('locked_until', $factor->getCasts());
        self::assertArrayNotHasKey('confirmed_at', $factor->getCasts());

        $factor->setRawAttributes(['held_until' => '2026-04-15 09:15:00', 'disabled_at' => '2026-04-15 09:00:00']);

        self::assertSame('2026-04-15 09:15:00', $factor->getLockedUntil()?->format('Y-m-d H:i:s'));
        self::assertSame('2026-04-15 09:00:00', $factor->getDisabledAt()?->format('Y-m-d H:i:s'));

        $remapped = new class extends Factor {
            /**
             * @return string
             */
            #[\Override]
            public function getDisabledAtName(): string
            {
                return 'switched_off_at';
            }
        };

        self::assertSame('datetime', $remapped->getCasts()['switched_off_at']);
    }

    /**
     * Declared either way; a time it reads to is a deadline whatever its class,
     * and the disabled time is still cast.
     *
     * @return void
     */
    public function testAModelsOwnCastOfTheDeadlineIsKept(): void
    {
        $method = new class extends Factor {
            /**
             * @return array<string, string>
             */
            #[\Override]
            protected function casts(): array
            {
                return ['locked_until' => 'immutable_datetime'];
            }
        };

        $property = new class extends Factor {
            /** @var array<string, string> The attributes that should be cast. */
            protected $casts = ['locked_until' => 'immutable_datetime'];

            /**
             * @return array<string, string>
             */
            #[\Override]
            protected function casts(): array
            {
                return [];
            }
        };

        foreach ([$method, $property] as $factor) {

            $factor->setRawAttributes(['locked_until' => '2026-04-15 09:15:00']);

            self::assertInstanceOf(CarbonImmutable::class, $factor->getLockedUntil());
            self::assertSame('2026-04-15 09:15:00', $factor->getLockedUntil()->format('Y-m-d H:i:s'));
            self::assertSame('datetime', $factor->getCasts()['disabled_at']);
        }
    }

    /**
     * @return iterable<string, array{string, mixed, class-string<\Throwable>}>
     */
    public static function unreadableTimes(): iterable
    {
        foreach (['the deadline' => 'held_until', 'the disabled time' => 'disabled_at'] as $name => $column) {
            yield $name . ', not a time' => [$column, 'not a time', InvalidFormatException::class];
            yield $name . ', empty' => [$column, '', InvalidModelException::class];
            yield $name . ', blank' => [$column, " \t", InvalidModelException::class];
        }
    }

    /**
     * Never read as no lockout or as enabled.
     *
     * @param  string  $column
     * @param  mixed  $stored
     * @param  class-string<\Throwable>  $exception
     * @return void
     */
    #[DataProvider('unreadableTimes')]
    public function testAnUnreadableTimeThrows(string $column, mixed $stored, string $exception): void
    {
        $factor = new RemappedLockoutFactor;

        $factor->setRawAttributes([$column => $stored]);

        $this->expectException($exception);

        $column === 'held_until' ? $factor->getLockedUntil() : $factor->getDisabledAt();
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function timesCastAsStrings(): iterable
    {
        yield 'the deadline' => ['locked_until', 'locked'];
        yield 'the disabled time' => ['disabled_at', 'disabled'];
    }

    /**
     * Naming the column and not the value.
     *
     * @param  string  $column
     * @param  string  $state
     * @return void
     */
    #[DataProvider('timesCastAsStrings')]
    public function testACastThatIsNotATimeThrows(string $column, string $state): void
    {
        $factor = new class extends Factor {
            /**
             * @return array<string, string>
             */
            #[\Override]
            protected function casts(): array
            {
                return ['locked_until' => 'string', 'disabled_at' => 'string'];
            }
        };

        $factor->setRawAttributes([$column => '2026-04-15 09:15:00']);

        $this->expectException(InvalidModelException::class);
        $this->expectExceptionMessage(sprintf('The factor\'s column [%s] does not read as a time, so whether it is %s cannot be told.', $column, $state));

        $column === 'locked_until' ? $factor->getLockedUntil() : $factor->getDisabledAt();
    }

    /**
     * On a model with or without a row.
     *
     * @return void
     */
    public function testNoTimeReadsAsNone(): void
    {
        $empty  = new RemappedLockoutFactor;
        $absent = (new RemappedLockoutFactor)->setRawAttributes(['held_until' => null, 'disabled_at' => null]);

        self::assertNull($empty->getLockedUntil());
        self::assertNull($empty->getDisabledAt());
        self::assertNull($absent->getLockedUntil());
        self::assertNull($absent->getDisabledAt());
    }

    /**
     * Public, as Eloquent's convention has it.
     *
     * @return void
     */
    public function testTheInitialiserKeepsACastAlreadyOnTheColumn(): void
    {
        $factor = new RemappedLockoutFactor;

        $factor->mergeCasts(['held_until' => 'immutable_datetime']);
        $factor->initializeActsAsFactor();

        self::assertSame('immutable_datetime', $factor->getCasts()['held_until']);
    }

    /**
     * @return void
     */
    public function testAuthenticatableReturnsMorphTo(): void
    {
        self::assertInstanceOf(MorphTo::class, (new Factor)->authenticatable());
    }

    /**
     * @return void
     */
    public function testGetTypeNameReturnsTypeColumn(): void
    {
        self::assertSame('type', (new Factor)->getTypeName());
    }

    /**
     * @return void
     */
    public function testGetLabelNameReturnsLabelColumn(): void
    {
        self::assertSame('label', (new Factor)->getLabelName());
    }

    /**
     * @return void
     */
    public function testGetDestinationNameReturnsDestinationColumn(): void
    {
        self::assertSame('destination', (new Factor)->getDestinationName());
    }

    /**
     * @return void
     */
    public function testGetSecretNameReturnsSecretColumn(): void
    {
        self::assertSame('secret', (new Factor)->getSecretName());
    }

    /**
     * @return void
     */
    public function testGetFactorIdentifierReturnsModelKey(): void
    {
        $factor     = new Factor;
        $factor->id = '01ABC';

        self::assertSame('01ABC', $factor->getFactorIdentifier());
    }

    /**
     * @return void
     */
    public function testGetTypeReturnsStringValue(): void
    {
        $factor = new Factor(['type' => 'totp']);

        self::assertSame('totp', $factor->getType());
    }

    /**
     * @return void
     */
    public function testGetTypeReturnsEmptyStringWhenUnset(): void
    {
        self::assertSame('', (new Factor)->getType());
    }

    /**
     * @return void
     */
    public function testGetLabelReturnsStringValue(): void
    {
        $factor = new Factor(['label' => 'Authenticator']);

        self::assertSame('Authenticator', $factor->getLabel());
    }

    /**
     * @return void
     */
    public function testGetLabelReturnsNullWhenUnset(): void
    {
        self::assertNull((new Factor)->getLabel());
    }

    /**
     * @return void
     */
    public function testGetDestinationReturnsStringValue(): void
    {
        $factor = new Factor(['destination' => 'user@example.com']);

        self::assertSame('user@example.com', $factor->getDestination());
    }

    /**
     * @return void
     */
    public function testGetDestinationReturnsNullWhenUnset(): void
    {
        self::assertNull((new Factor)->getDestination());
    }

    /**
     * @return void
     */
    public function testGetSecretReturnsStringValue(): void
    {
        $factor = new Factor(['secret' => 'plaintext']);

        self::assertSame('plaintext', $factor->getSecret());
    }

    /**
     * @return void
     */
    public function testGetSecretReturnsNullWhenUnset(): void
    {
        self::assertNull((new Factor)->getSecret());
    }

    /**
     * @return void
     */
    public function testRecordVerificationStampsLastUse(): void
    {
        $factor = $this->makeFullyPopulatedFactor();

        $factor->recordVerification();

        self::assertSame(Carbon::now()->getTimestamp(), $factor->getLastUsedAt()?->getTimestamp());
    }

    /**
     * The attempt service resets them under the identity's lock.
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
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function makeFullyPopulatedFactor(): Factor
    {
        return new Factor([
            'consecutive_failures' => 2,
        ]);
    }
}
