<?php

declare(strict_types = 1);

namespace Tests\Unit;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Assert;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Codes\MfaCodeMessage;
use SineMacula\Laravel\Mfa\Drivers\EmailDriver;
use SineMacula\Laravel\Mfa\Drivers\SmsDriver;
use SineMacula\Laravel\Mfa\Drivers\TotpDriver;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\RecoveryCodes\BackupCodeDriver;
use Tests\Fixtures\Codes\CustomMfaCodeMessage;
use Tests\Fixtures\Identities\TestUser;

/**
 * Unit tests for the `MfaManager` driver factories exposed via `driver($name)`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MfaManager::class)]
final class MfaManagerDriversTest extends MfaManagerTestCase
{
    /**
     * Resolving the TOTP driver should give a driver that reads the configured
     * settings in `config('mfa.totp')`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTotpDriverReadsTheConfiguredSettings(): void
    {
        $config = app(Repository::class);
        $config->set('mfa.totp', ['algorithm' => 'sha512', 'digits' => 8, 'period' => 60]);

        $driver = $this->manager()->driver('totp');

        self::assertInstanceOf(TotpDriver::class, $driver);

        $parameters = $driver->parameters();

        self::assertSame(['sha512', 8, 60], [$parameters->algorithm, $parameters->digits, $parameters->period]);
    }

    /**
     * Resolving the TOTP driver with no settings configured should fall back to
     * the defaults authenticator apps expect: SHA-1, 6 digits, 30 seconds.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTotpDriverDefaultsWhenUnset(): void
    {
        $config = app(Repository::class);
        $config->set('mfa.totp', []);

        $driver = $this->manager()->driver('totp');

        self::assertInstanceOf(TotpDriver::class, $driver);

        $parameters = $driver->parameters();

        self::assertSame(['sha1', 6, 30], [$parameters->algorithm, $parameters->digits, $parameters->period]);
    }

    /**
     * Resolving the email driver with an empty config slice should surface the
     * shipped defaults verbatim.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testEmailDriverBuildsWithDefaults(): void
    {
        $config = app(Repository::class);
        $config->set('mfa.codes', []);

        /** @var \SineMacula\Laravel\Mfa\Drivers\EmailDriver $driver */
        $driver = $this->manager()->driver('email');

        self::assertInstanceOf(EmailDriver::class, $driver);
        self::assertSame(MfaCodeMessage::class, $driver->getMailable());
    }

    /**
     * Resolving the email driver should apply the mailable override in the code
     * settings.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testEmailDriverBuildsWithConfiguredOverrides(): void
    {
        $config = app(Repository::class);
        $config->set('mfa.codes', [
            'mailable' => CustomMfaCodeMessage::class,
        ]);

        /** @var \SineMacula\Laravel\Mfa\Drivers\EmailDriver $driver */
        $driver = $this->manager()->driver('email');

        self::assertSame(CustomMfaCodeMessage::class, $driver->getMailable());
    }

    /**
     * Resolving the SMS driver with an empty config slice should surface the
     * shipped defaults verbatim.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testSmsDriverBuildsWithDefaults(): void
    {
        $config = app(Repository::class);
        $config->set('mfa.codes', []);

        /** @var \SineMacula\Laravel\Mfa\Drivers\SmsDriver $driver */
        $driver = $this->manager()->driver('sms');

        self::assertInstanceOf(SmsDriver::class, $driver);
        self::assertSame('Your verification code is: :code', $driver->getMessageTemplate());
    }

    /**
     * Resolving the SMS driver should apply the message override in the code
     * settings.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testSmsDriverBuildsWithConfiguredOverrides(): void
    {
        $config = app(Repository::class);
        $config->set('mfa.codes', [
            'sms_message' => 'Code: :code',
        ]);

        /** @var \SineMacula\Laravel\Mfa\Drivers\SmsDriver $driver */
        $driver = $this->manager()->driver('sms');

        self::assertSame('Code: :code', $driver->getMessageTemplate());
    }

    /**
     * Resolving the backup-code driver with an empty config slice should
     * surface the shipped defaults verbatim.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testBackupCodeDriverBuildsWithDefaults(): void
    {
        $config = app(Repository::class);
        $config->set('mfa.recovery_codes', []);

        /** @var \SineMacula\Laravel\Mfa\RecoveryCodes\BackupCodeDriver $driver */
        $driver = $this->manager()->driver('backup_code');

        self::assertInstanceOf(BackupCodeDriver::class, $driver);
        self::assertSame(12, $driver->getCodeLength());
        self::assertSame('23456789ABCDEFGHJKLMNPQRSTUVWXYZ', $driver->getAlphabet());
        self::assertSame(10, $driver->getCodeCount());
    }

    /**
     * Resolving the backup-code driver should apply every override in the
     * recovery code settings — length, alphabet and count.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testBackupCodeDriverBuildsWithConfiguredOverrides(): void
    {
        $config = app(Repository::class);
        $config->set('mfa.recovery_codes', [
            'length'   => 14,
            'alphabet' => 'ABCDEFGH',
            'count'    => 5,
        ]);

        /** @var \SineMacula\Laravel\Mfa\RecoveryCodes\BackupCodeDriver $driver */
        $driver = $this->manager()->driver('backup_code');

        self::assertSame(14, $driver->getCodeLength());
        self::assertSame('ABCDEFGH', $driver->getAlphabet());
        self::assertSame(5, $driver->getCodeCount());
    }

    /**
     * Verifying through an extension whose factory returns a non-`FactorDriver`
     * instance should surface a clear `LogicException` instead of a fatal type
     * error inside the verification pipeline.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testVerifyThrowsWhenExtendedDriverIsNotAFactorDriver(): void
    {
        // The base Manager's extend() accepts any callable returning mixed;
        // resolveDriver guards the FactorDriver contract at the boundary so a
        // misconfigured extension surfaces a LogicException rather than a fatal
        // type error deep inside verify().
        $manager = $this->manager();
        $manager->extend('not-a-driver', fn (): \stdClass => new \stdClass);

        $user = TestUser::query()->create([
            'email'       => 'extend@example.test',
            'mfa_enabled' => true,
        ]);
        $this->actingAs($user);

        // Stamp ownership AND driver onto the factor so the bad-driver guard
        // fires ahead of the ownership / driver-mismatch guards — the test's
        // subject is the LogicException raised when the extension factory
        // returns something that is not a FactorDriver, not a cross-account
        // rejection or a driver/factor identity mismatch.
        $factor                       = new Factor;
        $factor->type                 = 'not-a-driver';
        $factor->authenticatable_type = $user::class;
        $factor->authenticatable_id   = (string) $user->id;

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('Driver [not-a-driver] must implement');

        $manager->verify('not-a-driver', $factor, '000000');
    }

    /**
     * Resolve the package's MFA manager from the container.
     *
     * @return \SineMacula\Laravel\Mfa\MfaManager
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function manager(): MfaManager
    {
        $manager = $this->container()->make('mfa');
        Assert::assertInstanceOf(MfaManager::class, $manager);

        return $manager;
    }
}
