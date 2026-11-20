<?php

declare(strict_types = 1);

namespace Tests\Unit\Codes;

use Carbon\CarbonImmutable;
use Illuminate\Database\RecordsNotFoundException;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Codes\CodeSettings;
use SineMacula\Laravel\Mfa\Codes\SendLedger;
use SineMacula\Laravel\Mfa\Database\IdentityStateRow;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use Tests\TestCase;

/**
 * Waits are seconds, read with a two send destination cap, a three send
 * identity cap, a ten minute window and a one minute restart cooldown.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SendLedger::class)]
final class SendLedgerTest extends TestCase
{
    /**
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        CarbonImmutable::setTestNow('2026-11-01 12:00:00');

        config()->set('mfa.codes.factor_send_limit', 2);
        config()->set('mfa.codes.identity_send_limit', 3);
        config()->set('mfa.codes.send_window_minutes', 10);
        config()->set('mfa.codes.resend_cooldown_seconds', 60);

        foreach (['1', '2'] as $identity) {
            IdentityStateRow::lock(new ProofOwner('user', $identity), DB::connection());
        }
    }

    /**
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * Sent at 01:00 and 01:01 GMT, just after the clocks went back, both still
     * count at 01:04 GMT.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheWindowHoldsAcrossTheClocksGoingBack(): void
    {
        $this->useTimezone('Europe/London');

        CarbonImmutable::setTestNow(CarbonImmutable::parse('2026-10-25 01:04:00', 'UTC')->setTimezone('Europe/London'));

        $this->sent('1', ['destination-a' => [240, 180]]);

        self::assertSame(360, $this->ledger()->caps('destination-a', CarbonImmutable::now()));
    }

    /**
     * @return void
     *
     * @throws \JsonException
     */
    public function testSendsBelowBothCapsNeedNoWait(): void
    {
        $this->sent('1', ['destination-a' => [100], 'destination-b' => [50]]);

        self::assertSame(0, $this->ledger()->caps('destination-a', CarbonImmutable::now()));
    }

    /**
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheDestinationCapWaitsForItsOldestCountedSend(): void
    {
        $this->sent('1', ['destination-a' => [300, 100]]);

        self::assertSame(300, $this->ledger()->caps('destination-a', CarbonImmutable::now()));
    }

    /**
     * Across every destination the identity sent to.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheIdentityCapWaitsForItsOldestCountedSend(): void
    {
        $this->sent('1', ['destination-a' => [500], 'destination-b' => [400], 'destination-c' => [200]]);

        self::assertSame(100, $this->ledger()->caps('destination-d', CarbonImmutable::now()));
    }

    /**
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheLongerOfTheTwoWaitsApplies(): void
    {
        $this->sent('1', ['destination-a' => [100, 50], 'destination-b' => [550]]);

        self::assertSame(500, $this->ledger()->caps('destination-a', CarbonImmutable::now()));
        self::assertSame(50, $this->ledger()->caps('destination-b', CarbonImmutable::now()));
    }

    /**
     * Past a cap lowered since, until enough have left for one more.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testALoweredCapWaitsUntilEnoughSendsHaveLeft(): void
    {
        $this->sent('1', ['destination-a' => [500, 300, 100]]);

        self::assertSame(300, $this->ledger()->caps('destination-a', CarbonImmutable::now()));
    }

    /**
     * @return void
     *
     * @throws \JsonException
     */
    public function testASendBeforeTheWindowIsNotCounted(): void
    {
        $this->sent('1', ['destination-a' => [700, 601, 600]]);

        self::assertSame(0, $this->ledger()->caps('destination-a', CarbonImmutable::now()));
    }

    /**
     * @return void
     *
     * @throws \JsonException
     */
    public function testAnotherIdentitysSendsAreNotCounted(): void
    {
        $this->sent('2', ['destination-a' => [100, 50, 10]]);

        self::assertSame(0, $this->ledger()->caps('destination-a', CarbonImmutable::now()));
    }

    /**
     * From the latest enrolment send to the destination.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testARestartedEnrollmentWaitsOutTheCooldown(): void
    {
        $this->sent('1', ['destination-a' => [100, 20]], enrollment: true);
        $this->sent('1', ['destination-a' => [10]]);

        self::assertSame(40, $this->ledger()->restart('destination-a', Purpose::ENROLLMENT, CarbonImmutable::now()));
    }

    /**
     * Nor one with no enrolment send to the destination.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testOnlyAnEnrollmentWaitsToRestart(): void
    {
        $this->sent('1', ['destination-a' => [20]], enrollment: true);
        $this->sent('1', ['destination-b' => [20]]);

        self::assertSame(0, $this->ledger()->restart('destination-a', Purpose::SIGN_IN, CarbonImmutable::now()));
        self::assertSame(0, $this->ledger()->restart('destination-b', Purpose::ENROLLMENT, CarbonImmutable::now()));
    }

    /**
     * Only on the identity's own row.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testARecordedSendIsCountedByTheNextRead(): void
    {
        $now = CarbonImmutable::now();

        $this->ledger()->record('destination-a', Purpose::ENROLLMENT, $now->subSeconds(30));
        $this->ledger()->record('destination-a', Purpose::SIGN_IN, $now);

        self::assertSame([
            ['at' => $now->subSeconds(30)->getTimestamp(), 'to' => 'destination-a', 'enrollment' => true],
            ['at' => $now->getTimestamp(), 'to' => 'destination-a', 'enrollment' => false],
        ], self::sends('1'));
        self::assertSame(570, $this->ledger()->caps('destination-a', $now));
        self::assertSame(30, $this->ledger()->restart('destination-a', Purpose::ENROLLMENT, $now));
        self::assertNull(IdentityStateRow::of(new ProofOwner('user', '2'))->value('code_sends'));
    }

    /**
     * Those the window has passed go, and the rest stay a list.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testARecordDropsSendsTheWindowNoLongerCounts(): void
    {
        $this->sent('1', ['destination-a' => [700, 600, 599]]);

        $this->ledger()->record('destination-b', Purpose::SIGN_IN, CarbonImmutable::now());

        self::assertSame([599, 0], self::ages(self::sends('1')));
    }

    /**
     * Enrolment sends the cooldown still counts stay past a shorter window.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testARecordKeepsSendsTheCooldownStillCounts(): void
    {
        config()->set('mfa.codes.send_window_minutes', 1);
        config()->set('mfa.codes.resend_cooldown_seconds', 120);

        $this->sent('1', ['destination-a' => [120, 119]], enrollment: true);

        $this->ledger()->record('destination-b', Purpose::SIGN_IN, CarbonImmutable::now());

        self::assertSame([119, 0], self::ages(self::sends('1')));
    }

    /**
     * @return void
     *
     * @throws \JsonException
     */
    public function testAnIdentityWithoutAStateRowIsRefused(): void
    {
        $this->expectException(RecordsNotFoundException::class);

        SendLedger::read(new CodeSettings(config()), new ProofBinding('user', '3', 'web', 'session-a', Purpose::SIGN_IN));
    }

    /**
     * Each destination's sends the given seconds ago, written to the identity's
     * row after those already there.
     *
     * @param  string  $identity
     * @param  array<string, list<int>>  $secondsAgo
     * @param  bool  $enrollment
     * @return void
     *
     * @throws \JsonException
     */
    private function sent(string $identity, array $secondsAgo, bool $enrollment = false): void
    {
        $sends = self::sends($identity);

        foreach ($secondsAgo as $to => $ages) {
            foreach ($ages as $ago) {
                $sends[] = ['at' => CarbonImmutable::now()->subSeconds($ago)->getTimestamp(), 'to' => $to, 'enrollment' => $enrollment];
            }
        }

        IdentityStateRow::of(new ProofOwner('user', $identity))->update(['code_sends' => json_encode($sends, JSON_THROW_ON_ERROR)]);
    }

    /**
     * @param  string  $identity
     * @return list<array{at: int, to: string, enrollment: bool}>
     *
     * @throws \JsonException
     */
    private static function sends(string $identity): array
    {
        $sends = IdentityStateRow::of(new ProofOwner('user', $identity))->value('code_sends');

        /** @var list<array{at: int, to: string, enrollment: bool}> */
        return is_string($sends) ? json_decode($sends, true, flags: JSON_THROW_ON_ERROR) : [];
    }

    /**
     * @param  list<array{at: int, to: string, enrollment: bool}>  $sends
     * @return array<int, int>
     */
    private static function ages(array $sends): array
    {
        return array_map(static fn (array $send): int => CarbonImmutable::now()->getTimestamp() - $send['at'], $sends);
    }

    /**
     * The first identity's ledger as stored now.
     *
     * @return \SineMacula\Laravel\Mfa\Codes\SendLedger
     *
     * @throws \JsonException
     */
    private function ledger(): SendLedger
    {
        return SendLedger::read(new CodeSettings(config()), new ProofBinding('user', '1', 'web', 'session-a', Purpose::SIGN_IN));
    }
}
