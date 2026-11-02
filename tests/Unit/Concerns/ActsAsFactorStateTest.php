<?php

declare(strict_types = 1);

namespace Tests\Unit\Concerns;

use Carbon\Carbon;
use Illuminate\Foundation\Testing\RefreshDatabase;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Concerns\ActsAsFactor;
use SineMacula\Laravel\Mfa\Enums\FactorStatus;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;

/**
 * Unit tests for the parts of the `ActsAsFactor` trait that describe a factor
 * beyond its type and destination: its credential reference, TOTP parameters
 * and accepted step, status, preference, failures, the application it was
 * enrolled through, and when it was confirmed and last used.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversTrait(ActsAsFactor::class)]
final class ActsAsFactorStateTest extends TestCase
{
    use RefreshDatabase;

    /**
     * Clear the frozen clock.
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
     * Rows of a column-name accessor and the column it names.
     *
     * @return iterable<string, array{\Closure(\SineMacula\Laravel\Mfa\Models\Factor): string, string}>
     */
    public static function columns(): iterable
    {
        yield 'credential reference' => [static fn (Factor $factor): string => $factor->getCredentialReferenceName(), 'credential_reference'];
        yield 'TOTP algorithm' => [static fn (Factor $factor): string => $factor->getTotpAlgorithmName(), 'totp_algorithm'];
        yield 'TOTP digits' => [static fn (Factor $factor): string => $factor->getTotpDigitsName(), 'totp_digits'];
        yield 'TOTP period' => [static fn (Factor $factor): string => $factor->getTotpPeriodName(), 'totp_period'];
        yield 'last accepted step' => [static fn (Factor $factor): string => $factor->getLastAcceptedStepName(), 'last_accepted_step'];
        yield 'status' => [static fn (Factor $factor): string => $factor->getStatusName(), 'status'];
        yield 'preferred' => [static fn (Factor $factor): string => $factor->getPreferredName(), 'preferred'];
        yield 'consecutive failures' => [static fn (Factor $factor): string => $factor->getConsecutiveFailuresName(), 'consecutive_failures'];
        yield 'disabled at' => [static fn (Factor $factor): string => $factor->getDisabledAtName(), 'disabled_at'];
        yield 'locked until' => [static fn (Factor $factor): string => $factor->getLockedUntilName(), 'locked_until'];
        yield 'application' => [static fn (Factor $factor): string => $factor->getApplicationName(), 'application'];
        yield 'confirmed at' => [static fn (Factor $factor): string => $factor->getConfirmedAtName(), 'confirmed_at'];
        yield 'last used at' => [static fn (Factor $factor): string => $factor->getLastUsedAtName(), 'last_used_at'];
    }

    /**
     * Each column-name accessor names its column.
     *
     * @param  \Closure(\SineMacula\Laravel\Mfa\Models\Factor): string  $accessor
     * @param  string  $column
     * @return void
     */
    #[DataProvider('columns')]
    public function testEachColumnNameAccessorNamesItsColumn(\Closure $accessor, string $column): void
    {
        self::assertSame($column, $accessor(new Factor));
    }

    /**
     * A stored factor reads back every value it was stored with.
     *
     * @return void
     */
    public function testReadsBackEveryStoredValue(): void
    {
        $factor = $this->storedFactor([
            'credential_reference' => 'credential-1',
            'totp_algorithm'       => 'sha256',
            'totp_digits'          => 8,
            'totp_period'          => 60,
            'last_accepted_step'   => 59000000,
            'status'               => 'confirmed',
            'preferred'            => true,
            'consecutive_failures' => 4,
            'disabled_at'          => '2026-04-15 09:00:00',
            'locked_until'         => '2026-04-15 09:15:00',
            'application'          => 'web',
            'confirmed_at'         => '2026-04-15 08:00:00',
            'last_used_at'         => '2026-04-15 09:30:00',
        ]);

        self::assertSame('credential-1', $factor->getCredentialReference());
        self::assertSame('sha256', $factor->getTotpAlgorithm());
        self::assertSame(8, $factor->getTotpDigits());
        self::assertSame(60, $factor->getTotpPeriod());
        self::assertSame(59000000, $factor->getLastAcceptedStep());
        self::assertSame(FactorStatus::CONFIRMED, $factor->getStatus());
        self::assertTrue($factor->isConfirmed());
        self::assertTrue($factor->isPreferred());
        self::assertSame(4, $factor->getConsecutiveFailures());
        self::assertSame('2026-04-15 09:00:00', $factor->getDisabledAt()?->format('Y-m-d H:i:s'));
        self::assertSame('2026-04-15 09:15:00', $factor->getLockedUntil()?->format('Y-m-d H:i:s'));
        self::assertSame('web', $factor->getApplication());
        self::assertSame('2026-04-15 08:00:00', $factor->getConfirmedAt()?->format('Y-m-d H:i:s'));
        self::assertSame('2026-04-15 09:30:00', $factor->getLastUsedAt()?->format('Y-m-d H:i:s'));
    }

    /**
     * A new factor is pending, not preferred, has not failed, and holds nothing
     * else.
     *
     * @return void
     */
    public function testANewFactorIsPendingAndHoldsNothingElse(): void
    {
        $factor = $this->storedFactor([]);

        self::assertNull($factor->getCredentialReference());
        self::assertNull($factor->getTotpAlgorithm());
        self::assertNull($factor->getTotpDigits());
        self::assertNull($factor->getTotpPeriod());
        self::assertNull($factor->getLastAcceptedStep());
        self::assertSame(FactorStatus::PENDING, $factor->getStatus());
        self::assertFalse($factor->isConfirmed());
        self::assertFalse($factor->isPreferred());
        self::assertSame(0, $factor->getConsecutiveFailures());
        self::assertNull($factor->getDisabledAt());
        self::assertNull($factor->getLockedUntil());
        self::assertNull($factor->getApplication());
        self::assertNull($factor->getConfirmedAt());
        self::assertNull($factor->getLastUsedAt());
    }

    /**
     * An unset or unknown status reads as pending, never usable; a status cast
     * to the enum reads as the enum.
     *
     * @return void
     */
    public function testAnUnknownStatusIsPending(): void
    {
        $factor = new Factor;
        $factor->setRawAttributes(['status' => 'confirmed-ish']);

        self::assertSame(FactorStatus::PENDING, $factor->getStatus());

        $factor->setRawAttributes([]);

        self::assertSame(FactorStatus::PENDING, $factor->getStatus());

        $cast = new class extends Factor {
            /**
             * Cast the status to the enum.
             *
             * @return array<string, string>
             */
            #[\Override]
            protected function casts(): array
            {
                return ['status' => FactorStatus::class];
            }
        };
        $cast->setAttribute('status', FactorStatus::CONFIRMED);

        self::assertSame(FactorStatus::CONFIRMED, $cast->getStatus());
    }

    /**
     * A value of the wrong type reads as absent.
     *
     * @return void
     */
    public function testAValueOfTheWrongTypeReadsAsAbsent(): void
    {
        $factor = new class extends Factor {
            /**
             * Cast nothing, so the raw values are read as they are.
             *
             * @return array<string, string>
             */
            #[\Override]
            protected function casts(): array
            {
                return [];
            }
        };

        $factor->setRawAttributes([
            'credential_reference' => 5,
            'totp_digits'          => '6',
            'consecutive_failures' => '3',
            'disabled_at'          => '2026-04-15 09:00:00',
            'locked_until'         => '2026-04-15 09:15:00',
            'preferred'            => 1,
        ]);

        self::assertNull($factor->getCredentialReference());
        self::assertNull($factor->getTotpDigits());
        self::assertSame(0, $factor->getConsecutiveFailures());
        self::assertNull($factor->getDisabledAt());
        self::assertNull($factor->getLockedUntil());
        self::assertFalse($factor->isPreferred());
    }

    /**
     * Confirming marks the factor confirmed at the given time, or now.
     *
     * @return void
     */
    public function testConfirmingMarksTheFactorConfirmed(): void
    {
        Carbon::setTestNow('2026-04-15T10:00:00+00:00');

        $factor = new Factor;
        $factor->confirm();

        self::assertSame(FactorStatus::CONFIRMED, $factor->getStatus());
        self::assertSame('confirmed', $factor->getAttributes()['status']);
        self::assertSame('2026-04-15T10:00:00+00:00', $factor->getConfirmedAt()?->toIso8601String());

        $factor->confirm(Carbon::parse('2026-04-14T08:00:00+00:00'));

        self::assertSame('2026-04-14T08:00:00+00:00', $factor->getConfirmedAt()?->toIso8601String());
    }

    /**
     * A successful verification is the factor's last use too.
     *
     * @return void
     */
    public function testAVerificationIsTheLastUse(): void
    {
        Carbon::setTestNow('2026-04-15T10:00:00+00:00');

        $factor = new Factor;
        $factor->recordVerification();

        self::assertSame('2026-04-15T10:00:00+00:00', $factor->getLastUsedAt()?->toIso8601String());

        $factor->recordVerification(Carbon::parse('2026-04-14T08:00:00+00:00'));

        self::assertSame('2026-04-14T08:00:00+00:00', $factor->getLastUsedAt()?->toIso8601String());
    }

    /**
     * Store a factor with the given attributes and read it back.
     *
     * @param  array<string, mixed>  $attributes
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function storedFactor(array $attributes): Factor
    {
        $user = TestUser::query()->create(['email' => 'alice@example.test', 'mfa_enabled' => true]);

        $factor = Factor::query()->create([
            'authenticatable_type' => $user->getMorphClass(),
            'authenticatable_id'   => (string) $user->id,
            'type'                 => 'totp',
            ...$attributes,
        ]);

        return Factor::query()->findOrFail($factor->id);
    }
}
