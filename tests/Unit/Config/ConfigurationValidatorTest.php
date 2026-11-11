<?php

declare(strict_types = 1);

namespace Tests\Unit\Config;

use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use Illuminate\Contracts\Mail\Factory;
use Illuminate\Database\Eloquent\Model;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Applications\DeclaredFirstFactorResolver;
use SineMacula\Laravel\Mfa\Codes\MailEmailSender;
use SineMacula\Laravel\Mfa\Config\ConfigurationValidator;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\EmailSender;
use SineMacula\Laravel\Mfa\Contracts\FirstFactorResolver;
use SineMacula\Laravel\Mfa\Contracts\PasskeyGateway;
use SineMacula\Laravel\Mfa\Contracts\RecoveryCode;
use SineMacula\Laravel\Mfa\Contracts\SmsSender;
use SineMacula\Laravel\Mfa\Exceptions\InvalidConfigurationException;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Testing\FakeEmailSender;
use SineMacula\Laravel\Mfa\Testing\FakeSmsSender;
use Tests\Fixtures\Factors\SecondaryConnectionFactor;
use Tests\Fixtures\Passkeys\FakePasskeyGateway;
use Tests\Fixtures\RecoveryCodes\SecondaryConnectionRecoveryCode;
use Tests\TestCase;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConfigurationValidator::class)]
final class ConfigurationValidatorTest extends TestCase
{
    /** @var array<string, list<string>> What the report holds for the shipped configuration. */
    private const array SHIPPED = [
        'storage'        => [],
        'factor'         => [],
        'identity_state' => [],
        'totp'           => [],
        'codes'          => [],
        'recovery_codes' => [],
        'attempts'       => [],
        'enrollment'     => [],
        'passkeys'       => [],
        'lifecycle'      => [],
        'applications'   => [],
    ];

    /** @var string The problem of an application that neither declares nor resolves its first factor. */
    private const string NO_FIRST_FACTOR = 'The application declares no first_factor, and no ' . FirstFactorResolver::class . ' is bound to report it.';

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheShippedConfigurationHasNoProblem(): void
    {
        self::assertSame(self::SHIPPED, $this->validator()->report());

        $this->validator()->validate();
    }

    /**
     * @return iterable<string, array{string, mixed, string, string}>
     */
    public static function packageProblems(): iterable
    {
        yield 'a storage connection that is not configured' => [
            'mfa.storage.connection',
            'missing',
            'storage',
            'mfa.storage.connection names [missing], which database.connections does not configure.',
        ];
        yield 'a storage connection that is not a name' => [
            'mfa.storage.connection',
            5,
            'storage',
            '`mfa.storage.connection` must be a connection name, or null or empty for the default connection.',
        ];
        yield 'a factor model that is not one' => [
            'mfa.factor.model',
            \stdClass::class,
            'factor',
            sprintf('mfa.factor.model class [stdClass] must extend %s and implement %s.', Model::class, EloquentFactor::class),
        ];
        yield 'a factor model off the storage connection' => [
            'mfa.factor.model',
            SecondaryConnectionFactor::class,
            'factor',
            sprintf(
                'mfa.factor.model class [%s] must be on the storage connection (`mfa.storage.connection`): %s',
                SecondaryConnectionFactor::class,
                'the model is on [secondary], the package\'s tables on [testing].',
            ),
        ];
        yield 'a blank factor table' => ['mfa.factor.table', ' ', 'factor', 'mfa.factor.table must be a table name.'];
        yield 'a factor table that is not a string' => ['mfa.factor.table', ['mfa_factors'], 'factor', 'mfa.factor.table must be a table name.'];
        yield 'a blank identity state table' => ['mfa.identity_state.table', '', 'identity_state', 'mfa.identity_state.table must be a table name.'];
        yield 'a blank enrolment table' => ['mfa.enrollment.table', ' ', 'enrollment', 'mfa.enrollment.table must be a table name.'];
        yield 'a blank code table' => ['mfa.codes.table', '', 'codes', 'mfa.codes.table must be a table name.'];
        yield 'a recovery code table that is not a string' => ['mfa.recovery_codes.table', 5, 'recovery_codes', 'mfa.recovery_codes.table must be a table name.'];
        yield 'a blank attempt table' => ['mfa.attempts.table', ' ', 'attempts', 'mfa.attempts.table must be a table name.'];
        yield 'a blank passkey association table' => ['mfa.passkeys.table', ' ', 'passkeys', 'mfa.passkeys.table must be a table name.'];
        yield 'two tables sharing a name' => [
            'mfa.codes.table',
            'mfa_factors',
            'storage',
            'Each of the package\'s tables needs a name of its own: mfa.factor.table, mfa.codes.table share one.',
        ];
        yield 'a recovery code model that is not one' => [
            'mfa.recovery_codes.model',
            \stdClass::class,
            'recovery_codes',
            sprintf('mfa.recovery_codes.model class [stdClass] must extend %s and implement %s.', Model::class, RecoveryCode::class),
        ];
        yield 'a recovery code model off the storage connection' => [
            'mfa.recovery_codes.model',
            SecondaryConnectionRecoveryCode::class,
            'recovery_codes',
            sprintf(
                'mfa.recovery_codes.model class [%s] must be on the storage connection (`mfa.storage.connection`): %s',
                SecondaryConnectionRecoveryCode::class,
                'the model is on [secondary], the package\'s tables on [testing].',
            ),
        ];
        yield 'a TOTP setting' => ['mfa.totp.window', 4, 'totp', 'mfa.totp.window must be an integer from 0 to 3.'];
        yield 'a code setting' => ['mfa.codes.length', 5, 'codes', 'mfa.codes.length must be an integer from 6 to 10.'];
        yield 'a recovery code setting' => [
            'mfa.recovery_codes.length',
            6,
            'recovery_codes',
            'mfa.recovery_codes.length and mfa.recovery_codes.alphabet must give each code at least 40 bits of entropy after normalisation.',
        ];
        yield 'an attempt setting' => ['mfa.attempts.failure_ceiling', 101, 'attempts', 'mfa.attempts.failure_ceiling must be an integer from 1 to 100.'];
        yield 'an enrolment setting' => ['mfa.enrollment.ttl_minutes', 0, 'enrollment', 'mfa.enrollment.ttl_minutes must be an integer from 1 to 60.'];
        yield 'a lifecycle setting' => ['mfa.lifecycle.prune_after_days', 0, 'lifecycle', 'mfa.lifecycle.prune_after_days must be an integer from 1 to 3650.'];
        yield 'applications not keyed by name' => ['mfa.applications', [['types' => ['totp']]], 'applications', 'mfa.applications must be keyed by application name.'];
    }

    /**
     * The setting is put back afterwards so the test's migrations roll back.
     *
     * @param  string  $key
     * @param  mixed  $value
     * @param  string  $subject
     * @param  string  $problem
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('packageProblems')]
    public function testReportsAPackageWideProblemUnderItsSubject(string $key, mixed $value, string $subject, string $problem): void
    {
        $original = $this->config()->get($key);

        $this->config()->set($key, $value);

        try {
            $report = $this->validator()->report();
        } finally {
            $this->config()->set($key, $original);
        }

        $expected = [...self::SHIPPED, $subject => [$problem]];

        // The model checks read the storage connection too.
        if ($subject === 'storage' && !is_string($value)) {
            $expected['factor']         = [$problem];
            $expected['recovery_codes'] = [$problem];
        }

        self::assertSame($expected, $report);
    }

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testUnsetTablesAndConnectionHaveNoProblem(): void
    {
        $this->config()->set('mfa.factor', ['model' => Factor::class]);
        $this->config()->set('mfa.identity_state', []);
        $this->config()->set('mfa.storage.connection', 'testing');

        self::assertSame(self::SHIPPED, $this->validator()->report());
    }

    /**
     * The settings are put back afterwards so the test's migrations roll back.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAFactorModelOnTheStorageConnectionHasNoProblem(): void
    {
        $original = $this->config()->get('mfa');

        $this->config()->set('database.connections.secondary', ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']);
        $this->config()->set('mfa.storage.connection', 'secondary');

        try {
            $shipped = $this->validator()->report();

            $this->config()->set('mfa.factor.model', SecondaryConnectionFactor::class);

            $secondary = $this->validator()->report();
        } finally {
            $this->config()->set('mfa', $original);
        }

        self::assertSame(self::SHIPPED, $shipped);
        self::assertSame(self::SHIPPED, $secondary);
    }

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAWellConfiguredApplicationHasNoProblem(): void
    {
        $this->configureApplication(['types' => ['totp'], 'first_factor' => ['method' => 'password', 'channel' => 'password']]);

        self::assertSame([...self::SHIPPED, 'applications.web' => []], $this->validator()->report());
    }

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAnApplicationNeedsADeclaredOrResolvedFirstFactor(): void
    {
        $this->configureApplication(['types' => ['totp']]);

        self::assertSame([self::NO_FIRST_FACTOR], $this->validator()->report()['applications.web']);

        $this->container()->instance(FirstFactorResolver::class, \Mockery::mock(FirstFactorResolver::class));

        self::assertSame([], $this->validator()->report()['applications.web']);
    }

    /**
     * Any bound gateway is enough, even one that reports itself unavailable at
     * run time.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAPasskeyApplicationNeedsAGateway(): void
    {
        $this->configureApplication(['types' => ['passkey'], 'first_factor' => ['method' => 'password', 'channel' => 'password']]);

        self::assertSame(
            ['The application enables passkey, but no passkey gateway is bound: bind yours to ' . PasskeyGateway::class . '.'],
            $this->validator()->report()['applications.web'],
        );

        $this->container()->instance(PasskeyGateway::class, new FakePasskeyGateway(available: false));

        self::assertSame([], $this->validator()->report()['applications.web']);
    }

    /**
     * The default resolver reads the declaration, so binding it explicitly does
     * not stand in for one.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheDefaultResolverIsNoDeclaration(): void
    {
        $this->configureApplication(['types' => ['totp']]);

        $this->container()->singleton(FirstFactorResolver::class, DeclaredFirstFactorResolver::class);

        self::assertSame([self::NO_FIRST_FACTOR], $this->validator()->report()['applications.web']);
    }

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAnSmsApplicationNeedsASender(): void
    {
        $this->configureApplication(['types' => ['sms'], 'first_factor' => ['method' => 'password', 'channel' => 'password']]);

        self::assertSame(
            ['The application enables sms, but no SMS sender is bound: bind yours to ' . SmsSender::class . '.'],
            $this->validator()->report()['applications.web'],
        );

        FakeSmsSender::fake($this->container());

        self::assertSame([], $this->validator()->report()['applications.web']);
    }

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAnEmailApplicationNeedsASender(): void
    {
        $this->configureApplication(['types' => ['email'], 'first_factor' => ['method' => 'password', 'channel' => 'password']]);

        self::assertSame(
            ['The application enables email, but no email sender is bound: bind yours, or the package\'s MailEmailSender, to ' . EmailSender::class . '.'],
            $this->validator()->report()['applications.web'],
        );

        FakeEmailSender::fake($this->container());

        self::assertSame([], $this->validator()->report()['applications.web']);

        $this->container()->singleton(EmailSender::class, MailEmailSender::class);

        self::assertSame([], $this->validator()->report()['applications.web']);

        $this->configureApplication(['types' => ['totp'], 'first_factor' => ['method' => 'password', 'channel' => 'password']]);

        self::assertSame([], (new ConfigurationValidator(new Container, $this->config()))->report()['applications.web']);
    }

    /**
     * The check runs on every request, so it must not build a mail transport.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheEmailCheckBuildsNoMailTransport(): void
    {
        $this->configureApplication(['types' => ['email'], 'first_factor' => ['method' => 'password', 'channel' => 'password']]);

        /** @var \Illuminate\Contracts\Mail\Factory&\Mockery\MockInterface $mail */
        $mail = \Mockery::mock(Factory::class);
        $mail->shouldNotReceive('mailer');

        $this->container()->instance('mail.manager', $mail);
        $this->container()->singleton(EmailSender::class, MailEmailSender::class);

        self::assertSame([], $this->validator()->report()['applications.web']);
    }

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testACodeTypeNeedsAnApplicationKey(): void
    {
        FakeSmsSender::fake($this->container());

        $this->config()->set('app.key', null);
        $this->configureApplication(['types' => ['sms'], 'first_factor' => ['method' => 'password', 'channel' => 'password']]);

        self::assertSame(
            ['Delivered codes are hashed with a key derived from the application key; set app.key.'],
            $this->validator()->report()['applications.web'],
        );

        $this->configureApplication(['types' => ['totp'], 'first_factor' => ['method' => 'password', 'channel' => 'password']]);

        self::assertSame([], $this->validator()->report()['applications.web']);
    }

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testABrokenBindingIsReportedUnderItsSubject(): void
    {
        $this->configureApplication(['types' => ['sms'], 'first_factor' => ['method' => 'password', 'channel' => 'password']]);

        $this->container()->bind(SmsSender::class, 'App\Missing\Sender');

        $problems = $this->validator()->report()['applications.web'];

        self::assertCount(1, $problems);
        self::assertStringContainsString('App\Missing\Sender', $problems[0]);
    }

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAMalformedApplicationIsReportedOncePerProblem(): void
    {
        $this->configureApplication(['types' => 'totp']);

        self::assertSame([
            'mfa.applications.web.types must be a list of distinct factor type names.',
            self::NO_FIRST_FACTOR,
        ], $this->validator()->report()['applications.web']);
    }

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testEachApplicationIsASubject(): void
    {
        $this->config()->set('mfa.applications', [
            'web' => ['first_factor' => ['method' => 'password', 'channel' => 'password']],
            'api' => [],
        ]);

        self::assertSame([...self::SHIPPED, 'applications.web' => [], 'applications.api' => [self::NO_FIRST_FACTOR]], $this->validator()->report());
    }

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testValidateListsEveryProblem(): void
    {
        $this->config()->set('mfa.codes.length', 11);
        $this->configureApplication(['requirement' => 'often']);

        try {
            $this->validator()->validate();
            self::fail('Expected the configuration to be refused.');
        } catch (InvalidConfigurationException $exception) {
            self::assertSame([
                '[codes] mfa.codes.length must be an integer from 6 to 10.',
                '[applications.web] mfa.applications.web.requirement must be one of never, enrolled, always.',
                '[applications.web] ' . self::NO_FIRST_FACTOR,
            ], $exception->problems);
        }
    }

    /**
     * Configure the `web` application.
     *
     * @param  array<string, mixed>  $settings
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function configureApplication(array $settings): void
    {
        $this->config()->set('mfa.applications', ['web' => $settings]);
    }

    /**
     * @return \Illuminate\Config\Repository
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function config(): Repository
    {
        return $this->container()->make(Repository::class);
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Config\ConfigurationValidator
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function validator(): ConfigurationValidator
    {
        return $this->container()->make(ConfigurationValidator::class);
    }
}
