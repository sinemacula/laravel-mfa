<?php

declare(strict_types = 1);

namespace Tests\Unit;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository;
use PHPUnit\Framework\Assert;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Codes\MfaCodeMessage;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Drivers\EmailDriver;
use SineMacula\Laravel\Mfa\Drivers\SmsDriver;
use SineMacula\Laravel\Mfa\Drivers\TotpDriver;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Testing\FakeEmailSender;
use SineMacula\Laravel\Mfa\Verification\Submission;
use Tests\Fixtures\Codes\CustomMfaCodeMessage;
use Tests\Fixtures\Factors\InMemoryFactor;
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

        $sender = FakeEmailSender::fake($this->container());
        $driver = $this->manager()->driver('email');

        self::assertInstanceOf(EmailDriver::class, $driver);

        $driver->deliver(new InMemoryFactor(type: 'email', destination: 'ada@example.test'), '123456', CarbonImmutable::now()->addMinutes(5));

        self::assertSame(MfaCodeMessage::class, $sender->sent()[0]['message']::class);
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

        $sender = FakeEmailSender::fake($this->container());
        $driver = $this->manager()->driver('email');

        self::assertInstanceOf(EmailDriver::class, $driver);

        $driver->deliver(new InMemoryFactor(type: 'email', destination: 'ada@example.test'), '123456', CarbonImmutable::now()->addMinutes(5));

        self::assertInstanceOf(CustomMfaCodeMessage::class, $sender->sent()[0]['message']);
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
    }

    /**
     * Recovery codes are not a factor, so no driver is registered for them:
     * asking the manager for one fails as for any unknown driver.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testNoDriverIsRegisteredForRecoveryCodes(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Driver [recovery_code] not supported.');

        $this->manager()->driver('recovery_code');
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
        // the resolver guards the FactorDriver contract at the boundary so a
        // misconfigured extension surfaces a LogicException rather than a fatal
        // type error deep inside verify().
        $manager = $this->manager();
        $manager->extend('not-a-driver', fn (): \stdClass => new \stdClass);

        $user = TestUser::query()->create([
            'email'       => 'extend@example.test',
            'mfa_enabled' => true,
        ]);
        $this->actingAs($user);

        config()->set('mfa.applications.web', ['types' => ['not-a-driver'], 'first_factor' => ['method' => 'password', 'channel' => 'password']]);

        $factor = Factor::query()->create([
            'type'                 => 'not-a-driver',
            'status'               => 'confirmed',
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->id,
        ]);

        $this->container()->make(ProofStore::class)->begin($user, 'web', 'sign-in-1');

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('Driver [not-a-driver] must implement');

        $manager->verify(Submission::factor($factor->id, '000000'));
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
