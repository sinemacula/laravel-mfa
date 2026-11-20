<?php

declare(strict_types = 1);

namespace Tests\Integration;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Lifecycle\ForgetIdentity;
use SineMacula\Laravel\Mfa\Models\RecoveryCode;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeRows;
use SineMacula\Laravel\Mfa\Verification\Submission;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Enrollment\Concerns\ArrangesEnrollment;
use Tests\Fixtures\RecoveryCodes\CustomRecoveryCode;
use Tests\TestCase;

/**
 * Recovery codes are generated, redeemed, counted and forgotten through the
 * model `mfa.recovery_codes.model` names, on its own table and columns.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RecoveryCodeRows::class)]
#[CoversClass(ForgetIdentity::class)]
final class CustomRecoveryCodeModelTest extends TestCase
{
    use ArrangesEnrollment;

    /**
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeVerification();

        config()->set('mfa.recovery_codes.model', CustomRecoveryCode::class);
    }

    /**
     * @return void
     */
    public function testTheConfiguredModelHoldsEveryCode(): void
    {
        $user  = $this->steppedUpPerson();
        $first = Mfa::generateRecoveryCodes(Callers::current())->codes;
        $owner = ['owner_type' => $user->getMorphClass(), 'owner_id' => (string) $user->id];

        self::assertCount(10, $first);
        self::assertSame(10, DB::table('test_recovery_codes')->where($owner)->where('set_number', 1)->count());

        $code = $first[0]->reveal();

        self::assertTrue(Mfa::verify(Callers::current(), Submission::recoveryCode($code))->isVerified());
        self::assertTrue(Mfa::verify(Callers::current(), Submission::recoveryCode($code))->isFailed());
        self::assertSame(1, DB::table('test_recovery_codes')->whereNotNull('redeemed_at')->count());
        self::assertSame(9, Mfa::recoveryCodeStatus(Callers::current())?->remaining);

        $second = Mfa::generateRecoveryCodes(Callers::current())->codes;

        self::assertCount(10, $second);
        self::assertSame(10, DB::table('test_recovery_codes')->where($owner)->whereNotNull('retired_at')->count());
        self::assertTrue(Mfa::verify(Callers::current(), Submission::recoveryCode($first[1]->reveal()))->isFailed());
        self::assertTrue(Mfa::verify(Callers::current(), Submission::recoveryCode($second[0]->reveal()))->isVerified());
        self::assertSame(9, Mfa::recoveryCodeStatus(Callers::current())->remaining);
        self::assertSame(0, RecoveryCode::query()->count());

        Mfa::forgetIdentity($user);

        self::assertSame(0, DB::table('test_recovery_codes')->count());
        self::assertSame(0, RecoveryCode::query()->count());
    }
}
