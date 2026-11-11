<?php

declare(strict_types = 1);

namespace Tests\Unit;

use Illuminate\Config\Repository;
use Illuminate\Console\Application as ConsoleApplication;
use Illuminate\Container\Container;
use Illuminate\Events\Dispatcher;
use Illuminate\Foundation\Application;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\ServiceProvider;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Codes\CodeService;
use SineMacula\Laravel\Mfa\Codes\NullEmailSender;
use SineMacula\Laravel\Mfa\Codes\NullSmsSender;
use SineMacula\Laravel\Mfa\Console\CheckConfigurationCommand;
use SineMacula\Laravel\Mfa\Contracts\ActiveTenantResolver;
use SineMacula\Laravel\Mfa\Contracts\ChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\CombinationPolicy;
use SineMacula\Laravel\Mfa\Contracts\EmailSender;
use SineMacula\Laravel\Mfa\Contracts\EventContextResolver;
use SineMacula\Laravel\Mfa\Contracts\FirstFactorResolver;
use SineMacula\Laravel\Mfa\Contracts\FreshnessGate;
use SineMacula\Laravel\Mfa\Contracts\IdentityRequirement;
use SineMacula\Laravel\Mfa\Contracts\LastFactorPolicy;
use SineMacula\Laravel\Mfa\Contracts\PasskeyGateway;
use SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Contracts\Reauthenticator;
use SineMacula\Laravel\Mfa\Contracts\RequirementCheck;
use SineMacula\Laravel\Mfa\Contracts\RequirementPolicy;
use SineMacula\Laravel\Mfa\Contracts\SelfServiceRecovery;
use SineMacula\Laravel\Mfa\Contracts\SessionRevoker;
use SineMacula\Laravel\Mfa\Contracts\SessionTransition;
use SineMacula\Laravel\Mfa\Contracts\SmsSender;
use SineMacula\Laravel\Mfa\Contracts\SubjectTypeResolver;
use SineMacula\Laravel\Mfa\Contracts\TenantRequirement;
use SineMacula\Laravel\Mfa\Drivers\DriverResolver;
use SineMacula\Laravel\Mfa\Drivers\EmailDriver;
use SineMacula\Laravel\Mfa\Drivers\SmsDriver;
use SineMacula\Laravel\Mfa\Drivers\TotpDriver;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentService;
use SineMacula\Laravel\Mfa\Events\EventDispatcher;
use SineMacula\Laravel\Mfa\Exceptions\InvalidConfigurationException;
use SineMacula\Laravel\Mfa\Factors\FactorService;
use SineMacula\Laravel\Mfa\Http\Middleware\EnsureMfaRequirementIsMet;
use SineMacula\Laravel\Mfa\Http\Middleware\ExemptFromMfa;
use SineMacula\Laravel\Mfa\Http\MiddlewareSessionTransition;
use SineMacula\Laravel\Mfa\Lifecycle\LifecycleService;
use SineMacula\Laravel\Mfa\Lifecycle\NoSelfServiceRecovery;
use SineMacula\Laravel\Mfa\Lifecycle\RequiredFactorPolicy;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\MfaServiceProvider;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyChangeGate;
use SineMacula\Laravel\Mfa\Passkeys\UnavailablePasskeyGateway;
use SineMacula\Laravel\Mfa\Proofs\ProofService;
use SineMacula\Laravel\Mfa\Proofs\SessionProofStore;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService;
use SineMacula\Laravel\Mfa\Requirements\ConfiguredFreshnessGate;
use SineMacula\Laravel\Mfa\Requirements\ConfiguredRequirementPolicy;
use SineMacula\Laravel\Mfa\Requirements\IdentityContractRequirement;
use SineMacula\Laravel\Mfa\Requirements\NoTenantRequirement;
use SineMacula\Laravel\Mfa\Requirements\ProofRequirementCheck;
use SineMacula\Laravel\Mfa\Requirements\RequirementService;
use SineMacula\Laravel\Mfa\Seams\RefusingReauthenticator;
use SineMacula\Laravel\Mfa\Secrets\NoStore;
use SineMacula\Laravel\Mfa\Secrets\RedactSecretsInLogs;
use SineMacula\Laravel\Mfa\Verification\VerificationService;
use Tests\Fixtures\Factors\SecondaryConnectionFactor;
use Tests\TestCase;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MfaServiceProvider::class)]
final class MfaServiceProviderTest extends TestCase
{
    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testBindsMfaManagerAsSingletonUnderMfaAlias(): void
    {
        $first  = $this->container()->make('mfa');
        $second = $this->container()->make('mfa');

        self::assertInstanceOf(MfaManager::class, $first);
        self::assertSame($first, $second);
    }

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testBindsTheRequirementSeamsToTheirDefaults(): void
    {
        self::assertInstanceOf(ConfiguredRequirementPolicy::class, $this->container()->make(RequirementPolicy::class));
        self::assertInstanceOf(IdentityContractRequirement::class, $this->container()->make(IdentityRequirement::class));
        self::assertInstanceOf(NoTenantRequirement::class, $this->container()->make(TenantRequirement::class));
        self::assertInstanceOf(ProofRequirementCheck::class, $this->container()->make(RequirementCheck::class));
        self::assertInstanceOf(ConfiguredFreshnessGate::class, $this->container()->make(FreshnessGate::class));
    }

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testBindsProofStoreToSessionStore(): void
    {
        self::assertInstanceOf(
            SessionProofStore::class,
            $this->container()->make(ProofStore::class),
        );
    }

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testBindsTheSendersToTheNullSenders(): void
    {
        self::assertInstanceOf(NullSmsSender::class, $this->container()->make(SmsSender::class));
        self::assertInstanceOf(NullEmailSender::class, $this->container()->make(EmailSender::class));
    }

    /**
     * Each built on every resolution.
     *
     * @return void
     */
    public function testRegistersEachCapabilitysBindings(): void
    {
        $abstracts = [
            EventContextResolver::class,
            EventDispatcher::class,
            FactorService::class,
            DriverResolver::class,
            SmsSender::class,
            EmailSender::class,
            CodeService::class,
            CombinationPolicy::class,
            RequirementService::class,
            RequirementPolicy::class,
            IdentityRequirement::class,
            TenantRequirement::class,
            RequirementCheck::class,
            FreshnessGate::class,
            ProofService::class,
            VerificationService::class,
            EnrollmentService::class,
            LifecycleService::class,
            RecoveryCodeService::class,
            PendingSessionResolver::class,
            SubjectTypeResolver::class,
            Reauthenticator::class,
            FirstFactorResolver::class,
            SessionRevoker::class,
            SessionTransition::class,
            ChallengeGateway::class,
            PasskeyGateway::class,
            PasskeyChangeGate::class,
            LastFactorPolicy::class,
            ActiveTenantResolver::class,
            SelfServiceRecovery::class,
        ];

        foreach ($abstracts as $abstract) {
            self::assertFalse($this->container()->isShared($abstract), $abstract . ' must be built on every resolution.');
        }
    }

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRegistersTheShippedDrivers(): void
    {
        $manager = $this->container()->make('mfa');

        self::assertInstanceOf(MfaManager::class, $manager);
        self::assertInstanceOf(TotpDriver::class, $manager->driver('totp'));
        self::assertInstanceOf(EmailDriver::class, $manager->driver('email'));
        self::assertInstanceOf(SmsDriver::class, $manager->driver('sms'));
    }

    /**
     * Before anything is served, as one of the configuration's problems.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testBootRefusesAFactorModelOffTheStorageConnection(): void
    {
        $this->container()->make(Repository::class)->set('mfa.factor.model', SecondaryConnectionFactor::class);

        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('[factor] mfa.factor.model class [' . SecondaryConnectionFactor::class . '] must be on the storage connection');

        (new MfaServiceProvider($this->container()))->boot();
    }

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRegistersMiddlewareAliases(): void
    {
        /** @var \Illuminate\Routing\Router $router */
        $router = $this->container()->make(Router::class);

        $middleware = $router->getMiddleware();

        self::assertArrayHasKey('mfa', $middleware);
        self::assertArrayHasKey('mfa.exempt', $middleware);
        self::assertSame(EnsureMfaRequirementIsMet::class, $middleware['mfa']);
        self::assertSame(ExemptFromMfa::class, $middleware['mfa.exempt']);
    }

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testMergesDefaultMfaConfig(): void
    {
        $config = $this->container()->make('config');

        self::assertIsArray($config->get('mfa'));
        self::assertSame('mfa_factors', $config->get('mfa.factor.table'));
    }

    /**
     * @return void
     */
    public function testRegistersConfigPublishingTag(): void
    {
        $paths = ServiceProvider::pathsToPublish(
            null,
            'mfa-config',
        );

        self::assertNotEmpty($paths);
        self::assertContains(config_path('mfa.php'), $paths);
    }

    /**
     * @return void
     */
    public function testRegistersMigrationPublishingTag(): void
    {
        $paths = ServiceProvider::pathsToPublish(
            null,
            'mfa-migrations',
        );

        self::assertNotEmpty($paths);
    }

    /**
     * @return void
     */
    public function testLoadsTheTranslations(): void
    {
        self::assertSame('Your verification code', __('mfa::messages.email_subject'));
    }

    /**
     * To where Laravel looks for a package's overrides.
     *
     * @return void
     */
    public function testRegistersTranslationPublishingTag(): void
    {
        $paths = ServiceProvider::pathsToPublish(null, 'mfa-lang');

        self::assertContains($this->container()->langPath('vendor/mfa'), $paths);
        self::assertSame([$this->container()->langPath('vendor/mfa')], array_values($paths));
        self::assertFileExists((string) array_key_first($paths) . '/en/messages.php');
    }

    /**
     * @return void
     */
    public function testPublishesThePackagesOwnConfigurationAndMigrations(): void
    {
        $root      = dirname((string) (new \ReflectionClass(MfaServiceProvider::class))->getFileName(), 2);
        $publishes = [
            'mfa-config'     => [$root . '/config/mfa.php', config_path('mfa.php')],
            'mfa-migrations' => [$root . '/database/migrations', $this->container()->databasePath('migrations')],
        ];

        foreach ($publishes as $tag => [$source, $target]) {
            $paths = ServiceProvider::pathsToPublish(MfaServiceProvider::class, $tag);

            self::assertSame([$target], array_values($paths), $tag);
            self::assertSame(realpath($source), realpath((string) array_key_first($paths)), $tag);
        }
    }

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testBindsTheCapabilitiesSeamsToTheirDefaults(): void
    {
        $defaults = [
            Reauthenticator::class     => RefusingReauthenticator::class,
            LastFactorPolicy::class    => RequiredFactorPolicy::class,
            SelfServiceRecovery::class => NoSelfServiceRecovery::class,
            PasskeyGateway::class      => UnavailablePasskeyGateway::class,
            SessionTransition::class   => MiddlewareSessionTransition::class,
        ];

        foreach ($defaults as $abstract => $concrete) {
            self::assertInstanceOf($concrete, $this->container()->make($abstract), $abstract);
        }
    }

    /**
     * `mfa` and every default are bound only when nothing is bound yet.
     *
     * @return void
     */
    public function testRegisteringKeepsEveryEarlierBinding(): void
    {
        $container = $this->container();
        $earlier   = [];

        foreach (array_keys($container->getBindings()) as $abstract) {

            // Only the package's own: the framework's bindings serve the
            // provider's registration itself
            if ($abstract !== 'mfa' && !str_starts_with($abstract, 'SineMacula\Laravel\Mfa\\')) {
                continue;
            }

            $earlier[$abstract] = static fn (): \stdClass => new \stdClass;

            $container->bind($abstract, $earlier[$abstract]);
        }

        self::assertArrayHasKey('mfa', $earlier);
        self::assertArrayHasKey(ProofStore::class, $earlier);
        self::assertArrayHasKey(SessionTransition::class, $earlier);
        self::assertArrayHasKey(EnrollmentService::class, $earlier);

        (new MfaServiceProvider($container))->register();

        $bindings = $container->getBindings();

        foreach ($earlier as $abstract => $concrete) {
            self::assertSame($concrete, $bindings[$abstract]['concrete'] ?? null, $abstract . ' must keep the binding made before the provider registered.');
        }
    }

    /**
     * The middleware that stops a response holding a secret being stored, and
     * the log channels' redaction.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testBootRegistersTheSecretsProtections(): void
    {
        /** @var \Illuminate\Routing\Router $router */
        $router = $this->container()->make(Router::class);

        self::assertSame(NoStore::class, $router->getMiddleware()['mfa.no-store'] ?? null);

        $channels = config('logging.channels');

        self::assertIsArray($channels);
        self::assertNotSame([], $channels);

        foreach ($channels as $name => $channel) {
            self::assertIsArray($channel);

            $taps = $channel['tap'] ?? [];

            self::assertIsArray($taps);
            self::assertContains(RedactSecretsInLogs::class, $taps, (string) $name);
        }
    }

    /**
     * No configuration could cover every locale.
     *
     * @return void
     */
    public function testTheSmsWordingIsNotConfigured(): void
    {
        self::assertFalse(config()->has('mfa.codes.sms_message'));
        self::assertTrue(config()->has('mfa.codes.mailable'));
    }

    /**
     * @return void
     *
     * @throws \ReflectionException
     */
    public function testOfferPublishingIsSkippedWhenNotRunningInConsole(): void
    {
        // A kernel whose `runningInConsole()` is false reaches the early return
        // in `offerPublishing()`.
        $app = new class extends Application {
            /**
             * @imperative
             *
             * @return bool
             */
            #[\Override]
            public function runningInConsole(): bool
            {
                return false;
            }
        };

        // `runningInConsole()` short-circuits before the config is read, so an
        // empty repository is enough.
        $app->bind('config', static fn () => new Repository(['mfa' => []]));
        $app->bind(Router::class, static fn ($app) => new Router(
            new Dispatcher($app),
        ));

        // Other tests share the static registry, so compare before and after.
        $providerClass = MfaServiceProvider::class;

        /** @var array<string, mixed> $before */
        $before = ServiceProvider::$publishes[$providerClass] ?? [];

        $bootstrappers = new \ReflectionProperty(ConsoleApplication::class, 'bootstrappers');
        $starting      = $bootstrappers->getValue();

        $provider = new MfaServiceProvider($app);

        $provider->boot();

        /** @var array<string, mixed> $after */
        $after = ServiceProvider::$publishes[$providerClass] ?? [];

        self::assertSame(
            $before,
            $after,
            'offerPublishing() must not register publishes under a non-console kernel',
        );

        self::assertSame($starting, $bootstrappers->getValue(), 'registerCommands() must not register commands under a non-console kernel');
    }

    /**
     * @return void
     */
    public function testRegistersTheCheckCommand(): void
    {
        self::assertInstanceOf(CheckConfigurationCommand::class, Artisan::all()['mfa:check'] ?? null);
    }

    /**
     * Refusing one out of range before anything is served.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testBootRefusesAnInvalidConfiguration(): void
    {
        $this->container()->make(Repository::class)->set('mfa.recovery_codes.count', 0);

        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('[recovery_codes] mfa.recovery_codes.count must be an integer from 1 to 50.');

        (new MfaServiceProvider($this->container()))->boot();
    }

    /**
     * So a setting changed after boot fails there rather than at a first
     * verification.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testResolvingTheManagerRefusesAnInvalidConfiguration(): void
    {
        $this->container()->forgetInstance('mfa');
        $this->container()->make(Repository::class)->set('mfa.attempts.lockout_seconds', 30);

        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('[attempts] mfa.attempts.lockout_seconds must be an integer from 60 to 86400.');

        $this->container()->make('mfa');
    }

    /**
     * The defaults this package binds, by class or by its own closure.
     *
     * @return void
     */
    public function testTheShippedDefaultsAreThePackages(): void
    {
        foreach ([SmsSender::class, ProofStore::class, PasskeyGateway::class, SessionRevoker::class] as $contract) {
            self::assertTrue(MfaServiceProvider::isPackageDefault($this->container(), $contract), $contract);
        }
    }

    /**
     * No default is shared, so resolving one leaves it the default.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAResolvedDefaultIsStillThePackages(): void
    {
        foreach ([SmsSender::class, ProofStore::class, PasskeyGateway::class, SessionRevoker::class] as $contract) {
            $this->container()->make($contract);

            self::assertTrue(MfaServiceProvider::isPackageDefault($this->container(), $contract), $contract);
        }
    }

    /**
     * Ways an application binds, holds or changes a contract.
     *
     * @return iterable<string, array{\Closure(\Illuminate\Container\Container): void}>
     */
    public static function applicationBindings(): iterable
    {
        yield 'unbound' => [static function (): void {}];
        yield 'another class' => [static fn (Container $container) => $container->bind('contract', \stdClass::class)];
        yield 'a closure' => [static fn (Container $container) => $container->bind('contract', static fn (): \stdClass => new \stdClass)];
        yield 'shared' => [static fn (Container $container) => $container->singleton('contract', NullSmsSender::class)];
        yield 'an instance' => [static function (Container $container): void {
            $container->bind('contract', NullSmsSender::class);
            $container->instance('contract', new NullSmsSender);
        }];
        yield 'an alias' => [static function (Container $container): void {
            $container->bind('contract', NullSmsSender::class);
            $container->alias(\stdClass::class, 'contract');
        }];
        yield 'an extender' => [static function (Container $container): void {
            $container->bind('contract', NullSmsSender::class);
            $container->extend('contract', static fn (object $sender): object => $sender);
        }];
        yield 'the class rebound' => [static function (Container $container): void {
            $container->bind('contract', NullSmsSender::class);
            $container->bind(NullSmsSender::class, \stdClass::class);
        }];
    }

    /**
     * Anything an application binds, holds or changes is not the default.
     *
     * @param  \Closure(\Illuminate\Container\Container): void  $arrange
     * @return void
     */
    #[DataProvider('applicationBindings')]
    public function testAnApplicationsBindingIsNotThePackages(\Closure $arrange): void
    {
        $container = new Container;

        $arrange($container);

        self::assertFalse(MfaServiceProvider::isPackageDefault($container, 'contract'));
    }

    /**
     * A package class bound by name counts as the default, whoever bound it.
     *
     * @return void
     */
    public function testAPackageClassBoundByNameIsThePackages(): void
    {
        $container = new Container;

        $container->bind(SmsSender::class, NullSmsSender::class);

        self::assertTrue(MfaServiceProvider::isPackageDefault($container, SmsSender::class));
    }
}
