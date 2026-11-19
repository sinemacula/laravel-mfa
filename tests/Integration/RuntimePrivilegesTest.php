<?php

declare(strict_types = 1);

namespace Tests\Integration;

use Carbon\Carbon;
use Carbon\CarbonImmutable;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Events\Actor;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use SineMacula\Laravel\Mfa\Verification\Submission;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Enrollment\Concerns\ArrangesEnrollment;
use Tests\TestCase;

/**
 * The runtime database user needs only SELECT, INSERT, UPDATE and DELETE on the
 * migrated tables.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MfaManager::class)]
final class RuntimePrivilegesTest extends TestCase
{
    use ArrangesEnrollment;

    /** @var list<string> Every statement run since setup, oldest first. */
    private array $statements = [];

    /**
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeVerification();

        DB::listen(function (QueryExecuted $query): void {
            $this->statements[] = $query->sql;
        });
    }

    /**
     * @return void
     */
    public function testEnrollingAndConfirmingIssuesOnlyDataStatements(): void
    {
        $this->reauthenticatedPerson();

        $start = $this->startedTotp();

        self::assertTrue(Mfa::confirmEnrollment(Callers::current(), $this->grantOf($start), $this->appCode($start))->isConfirmed());

        $this->assertOnlyDataStatements();
    }

    /**
     * @return void
     */
    public function testSendingAndVerifyingACodeIssuesOnlyDataStatements(): void
    {
        $factor = $this->emailFactor($this->signedInPerson());

        [$challenge, $code] = $this->sentCode($factor);

        self::assertTrue(Mfa::verify(Callers::current(), Submission::challenge($factor->id, $challenge, $code))->isVerified());

        $this->assertOnlyDataStatements();
    }

    /**
     * @return void
     */
    public function testALockoutIssuesOnlyDataStatements(): void
    {
        config()->set('mfa.attempts.factor_limit', 2);

        $this->requestFrom('203.0.113.9');

        $factor = $this->totpFactor($this->signedInPerson());

        Mfa::verify(Callers::current(), Submission::factor($factor->id, '000000'));
        Mfa::verify(Callers::current(), Submission::factor($factor->id, '000000'));

        self::assertSame(FailureReason::LOCKED, Mfa::verify(Callers::current(), Submission::factor($factor->id, AuthenticatorApp::code($factor)))->reason);

        $this->assertOnlyDataStatements();
    }

    /**
     * @return void
     */
    public function testGeneratingAndRedeemingRecoveryCodesIssuesOnlyDataStatements(): void
    {
        $this->steppedUpPerson();

        $codes = Mfa::generateRecoveryCodes(Callers::current())->codes;

        self::assertTrue(Mfa::verify(Callers::current(), Submission::recoveryCode($codes[0]->reveal()))->isVerified());

        $this->assertOnlyDataStatements();
    }

    /**
     * @return void
     */
    public function testPruningIssuesOnlyDataStatements(): void
    {
        $this->requestFrom('203.0.113.9');

        $user = $this->reauthenticatedPerson();

        $this->startedTotp();

        $factor = $this->emailFactor($user);

        [$challenge] = $this->sentCode($factor);

        Mfa::verify(Callers::current(), Submission::challenge($factor->id, $challenge, '000000'));

        $this->recoveryCode($user);
        $this->recoveryCode($user);

        Carbon::setTestNow(CarbonImmutable::now()->addDays(31));

        $pruned = Mfa::prune();

        self::assertSame([1, 1, 10, 2], [$pruned->enrollments, $pruned->codes, $pruned->recoveryCodes, $pruned->attempts]);

        $this->assertOnlyDataStatements();
    }

    /**
     * @return void
     */
    public function testResettingAndForgettingIssueOnlyDataStatements(): void
    {
        $user = $this->signedInPerson();

        $this->totpFactor($user);
        $this->recoveryCode($user);

        Mfa::resetIdentity($user, new Actor('admin', '9'), 'Lost phone.');
        Mfa::forgetIdentity($user);

        $this->assertOnlyDataStatements();
    }

    /**
     * Locking reads are selects; no DDL, LOCK TABLES or SET.
     *
     * @return void
     */
    private function assertOnlyDataStatements(): void
    {
        self::assertNotSame([], $this->statements);

        foreach ($this->statements as $sql) {
            self::assertMatchesRegularExpression('/^\s*(select|insert|update|delete)\s/i', $sql);
        }
    }
}
