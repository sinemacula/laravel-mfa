<?php

declare(strict_types = 1);

namespace Tests\Integration\Database;

use Illuminate\Config\Repository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Attempts\AttemptService;
use SineMacula\Laravel\Mfa\Attempts\AttemptStore;
use SineMacula\Laravel\Mfa\Database\TableNames;
use SineMacula\Laravel\Mfa\Enums\AttemptScope;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use SineMacula\Laravel\Mfa\Verification\Submission;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Enrollment\Concerns\ArrangesEnrollment;
use Tests\TestCase;

/**
 * Every table renamed, on a storage connection with a table prefix.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AttemptStore::class)]
#[CoversClass(TableNames::class)]
final class RenamedTablesTest extends TestCase
{
    use ArrangesEnrollment;

    /** @var string */
    private const string PREFIX = 'app_';

    /**
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeVerification();
    }

    /**
     * @return void
     */
    public function testOnlyThePrefixedRenamedTablesExist(): void
    {
        $tables = array_column(Schema::getTables(), 'name');

        foreach (array_keys(TableNames::DEFAULTS) as $block) {
            $renamed = self::renamed($block);

            self::assertContains(self::PREFIX . $renamed, $tables);
            self::assertNotContains($renamed, $tables);
            self::assertFalse(Schema::hasTable(TableNames::DEFAULTS[$block]));
        }
    }

    /**
     * @return void
     */
    public function testTheAddressAndIdentityThrottlesTrip(): void
    {
        config()->set('mfa.attempts.factor_limit', 10);
        config()->set('mfa.attempts.identity_limit', 3);
        config()->set('mfa.attempts.ip_limit', 2);

        $user   = $this->signedInPerson();
        $factor = $this->totpFactor($user);

        $this->requestFrom('203.0.113.9');

        self::assertSame(FailureReason::INVALID_CODE, Mfa::verify(Callers::current(), Submission::factor($factor->id, '000000'))->reason);
        self::assertSame(FailureReason::INVALID_CODE, Mfa::verify(Callers::current(), Submission::factor($factor->id, '000000'))->reason);
        self::assertSame(FailureReason::LOCKED, Mfa::verify(Callers::current(), Submission::factor($factor->id, AuthenticatorApp::code($factor)))->reason);
        self::assertSame(2, $this->addressHits('203.0.113.9'));
        self::assertSame(2, $this->factorRun($factor));

        $this->requestFrom('198.51.100.7');

        self::assertSame(FailureReason::INVALID_CODE, Mfa::verify(Callers::current(), Submission::factor($factor->id, '000000'))->reason);
        self::assertSame(FailureReason::LOCKED, Mfa::verify(Callers::current(), Submission::factor($factor->id, AuthenticatorApp::code($factor)))->reason);
        self::assertSame(AttemptScope::IDENTITY, $this->container()->make(AttemptService::class)->lockout($user)?->scope);
        self::assertSame(3, $this->identityRun($user));
        self::assertSame(3, DB::table(self::renamed(TableNames::ATTEMPTS))->count());
        self::assertSame(1, DB::table(self::renamed(TableNames::IDENTITY_STATES))->whereNotNull('locked_until')->count());
    }

    /**
     * @return void
     */
    public function testCodesAndRecoveryCodesVerify(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->emailFactor($user);

        [$challenge, $code] = $this->sentCode($factor);

        self::assertTrue(Mfa::verify(Callers::current(), Submission::challenge($factor->id, $challenge, $code))->isVerified());
        self::assertSame(FailureReason::REPLAYED, Mfa::verify(Callers::current(), Submission::challenge($factor->id, $challenge, $code))->reason);
        self::assertSame(1, DB::table(self::renamed(TableNames::CODES))->count());

        self::assertTrue(Mfa::verify(Callers::current(), Submission::recoveryCode($this->recoveryCode($user)))->isVerified());
        self::assertSame(9, Mfa::recoveryCodeStatus(Callers::current())?->remaining);
    }

    /**
     * @return void
     */
    public function testEnrollingAndPasskeysUseTheRenamedTables(): void
    {
        $user  = $this->reauthenticatedPerson();
        $start = $this->startedTotp();

        self::assertSame(1, DB::table(self::renamed(TableNames::ENROLLMENTS))->count());
        self::assertTrue(Mfa::confirmEnrollment(Callers::current(), $this->grantOf($start), $this->appCode($start))->isConfirmed());
        self::assertSame(0, DB::table(self::renamed(TableNames::ENROLLMENTS))->count());

        $this->enablePasskeys();

        self::assertTrue(Mfa::verify(Callers::current(), $this->passingSubmission($user, 'passkey'))->isVerified());
        self::assertSame(1, DB::table(self::renamed(TableNames::PASSKEY_ASSOCIATIONS))->count());
    }

    /**
     * @param  mixed  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(Repository::class);

        $config->set('database.connections.testing.prefix', self::PREFIX);

        foreach (array_keys(TableNames::DEFAULTS) as $block) {
            $config->set(TableNames::setting($block), self::renamed($block));
        }
    }

    /**
     * @param  string  $block
     * @return string
     */
    private static function renamed(string $block): string
    {
        return 'auth_' . substr(TableNames::DEFAULTS[$block], 4);
    }
}
