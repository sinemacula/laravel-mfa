<?php

declare(strict_types = 1);

namespace Tests\Unit;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Assert;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\FactorDriver;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Drivers\EmailDriver;
use SineMacula\Laravel\Mfa\Drivers\SmsDriver;
use SineMacula\Laravel\Mfa\Drivers\TotpDriver;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Testing\FakeEmailSender;
use SineMacula\Laravel\Mfa\Verification\Submission;
use Tests\Fixtures\Codes\CodeMessages;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Drivers\Enums\NumberedDriver;
use Tests\Fixtures\Drivers\NoopFactorDriver;
use Tests\Fixtures\Factors\InMemoryFactor;
use Tests\Fixtures\Identities\TestUser;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MfaManager::class)]
final class MfaManagerDriversTest extends MfaManagerTestCase
{
    /**
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
     * SHA-1, 6 digits, 30 seconds: what authenticator apps expect.
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
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testEmailDriverSendsThroughTheBoundSender(): void
    {
        $sender  = FakeEmailSender::fake($this->container());
        $driver  = $this->manager()->driver('email');
        $message = CodeMessages::to('ada@example.test');

        self::assertInstanceOf(EmailDriver::class, $driver);

        $driver->deliver(new InMemoryFactor(type: 'email', destination: 'ada@example.test'), $message);

        self::assertSame([$message], $sender->sent());
    }

    /**
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
     * Recovery codes are not a factor, so asking for their driver fails as for
     * any unknown one.
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
     * As Laravel's manager names it.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAnIntegerBackedEnumNamesTheDriverOfItsValue(): void
    {
        $manager = $this->manager();
        $driver  = new NoopFactorDriver;

        $manager->extend('1', fn (): FactorDriver => $driver);

        self::assertSame($driver, $manager->driver(NumberedDriver::FIRST));
    }

    /**
     * A `LogicException` rather than a fatal type error inside verification.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testVerifyThrowsWhenExtendedDriverIsNotAFactorDriver(): void
    {
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

        $manager->verify(Callers::current(), Submission::factor($factor->id, '000000'));
    }

    /**
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
