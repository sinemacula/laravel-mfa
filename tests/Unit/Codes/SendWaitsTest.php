<?php

declare(strict_types = 1);

namespace Tests\Unit\Codes;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Codes\CodeSettings;
use SineMacula\Laravel\Mfa\Codes\SendWaits;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Models\Code;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
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
#[CoversClass(SendWaits::class)]
final class SendWaitsTest extends TestCase
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
     */
    public function testTheWindowHoldsAcrossTheClocksGoingBack(): void
    {
        $this->useTimezone('Europe/London');

        CarbonImmutable::setTestNow(CarbonImmutable::parse('2026-10-25 01:04:00', 'UTC')->setTimezone('Europe/London'));

        $this->send('destination-a', self::binding(), [240, 180]);

        self::assertSame(360, $this->waits()->caps('destination-a', self::binding(), CarbonImmutable::now()));
    }

    /**
     * @return void
     */
    public function testSendsBelowBothCapsNeedNoWait(): void
    {
        $this->send('destination-a', self::binding(), [100]);
        $this->send('destination-b', self::binding(), [50]);

        self::assertSame(0, $this->waits()->caps('destination-a', self::binding(), CarbonImmutable::now()));
    }

    /**
     * Until the oldest of the counted sends leaves the window, from any
     * identity or session.
     *
     * @return void
     */
    public function testTheDestinationCapWaitsForItsOldestCountedSend(): void
    {
        $this->send('destination-a', self::binding(identity: '2'), [300]);
        $this->send('destination-a', self::binding(identity: '3', session: 'session-b'), [100]);

        self::assertSame(300, $this->waits()->caps('destination-a', self::binding(), CarbonImmutable::now()));
    }

    /**
     * Across every destination the identity sent to.
     *
     * @return void
     */
    public function testTheIdentityCapWaitsForItsOldestCountedSend(): void
    {
        $this->send('destination-a', self::binding(), [500]);
        $this->send('destination-b', self::binding(), [400]);
        $this->send('destination-c', self::binding(session: 'session-b'), [200]);

        self::assertSame(100, $this->waits()->caps('destination-d', self::binding(), CarbonImmutable::now()));
    }

    /**
     * @return void
     */
    public function testTheLongerOfTheTwoWaitsApplies(): void
    {
        $this->send('destination-a', self::binding(identity: '2'), [100, 50]);
        $this->send('destination-b', self::binding(), [550, 540, 530]);

        self::assertSame(500, $this->waits()->caps('destination-a', self::binding(), CarbonImmutable::now()));
        self::assertSame(60, $this->waits()->caps('destination-b', self::binding(), CarbonImmutable::now()));
    }

    /**
     * @return void
     */
    public function testASendBeforeTheWindowIsNotCounted(): void
    {
        $this->send('destination-a', self::binding(), [700]);
        $this->send('destination-a', self::binding(), [601]);
        $this->send('destination-a', self::binding(), [600]);

        self::assertSame(0, $this->waits()->caps('destination-a', self::binding(), CarbonImmutable::now()));
    }

    /**
     * From the latest enrolment send to the destination.
     *
     * @return void
     */
    public function testARestartedEnrollmentWaitsOutTheCooldown(): void
    {
        $enrollment = self::binding(purpose: Purpose::ENROLLMENT);

        $this->send('destination-a', $enrollment, [100]);
        $this->send('destination-a', self::binding(identity: '2', purpose: Purpose::ENROLLMENT), [20]);
        $this->send('destination-a', self::binding(), [10]);

        self::assertSame(40, $this->waits()->restart('destination-a', $enrollment, CarbonImmutable::now()));
    }

    /**
     * Nor one with no enrolment send to the destination.
     *
     * @return void
     */
    public function testOnlyAnEnrollmentWaitsToRestart(): void
    {
        $this->send('destination-a', self::binding(purpose: Purpose::ENROLLMENT), [20]);
        $this->send('destination-b', self::binding(), [20]);

        self::assertSame(0, $this->waits()->restart('destination-a', self::binding(), CarbonImmutable::now()));
        self::assertSame(0, $this->waits()->restart('destination-b', self::binding(purpose: Purpose::ENROLLMENT), CarbonImmutable::now()));
    }

    /**
     * @param  string  $identity
     * @param  string  $session
     * @param  \SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @return \SineMacula\Laravel\Mfa\Proofs\ProofBinding
     */
    private static function binding(string $identity = '1', string $session = 'session-a', Purpose $purpose = Purpose::SIGN_IN): ProofBinding
    {
        return new ProofBinding('user', $identity, 'web', $session, $purpose);
    }

    /**
     * One code row whose sends were the given seconds ago, the last of them
     * latest.
     *
     * @param  string  $destination
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  non-empty-list<int>  $secondsAgo
     * @return void
     */
    private function send(string $destination, ProofBinding $binding, array $secondsAgo): void
    {
        $now   = CarbonImmutable::now();
        $times = array_map(static fn (int $ago): int => $now->subSeconds($ago)->getTimestamp(), $secondsAgo);

        Code::query()->create([
            'factor_id'            => 'factor-1',
            'authenticatable_type' => $binding->identityType,
            'authenticatable_id'   => $binding->identityKey,
            'purpose'              => $binding->purpose->value,
            'application'          => $binding->application,
            'session_id'           => $binding->sessionId,
            'destination_hash'     => $destination,
            'code_hash'            => str_repeat('0', 64),
            'sends'                => count($times),
            'sent_at'              => $now->subSeconds(min($secondsAgo)),
            'sent_times'           => $times,
            'expires_at'           => $now->addMinutes(10),
        ]);
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Codes\SendWaits
     */
    private function waits(): SendWaits
    {
        return new SendWaits(new CodeSettings(config()));
    }
}
