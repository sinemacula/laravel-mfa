<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Config;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\BindingResolutionException;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Mail\Mailer;
use SineMacula\Laravel\Mfa\Applications\ApplicationSettings;
use SineMacula\Laravel\Mfa\Attempts\AttemptSettings;
use SineMacula\Laravel\Mfa\Codes\CodeSettings;
use SineMacula\Laravel\Mfa\Codes\NullSmsGateway;
use SineMacula\Laravel\Mfa\Contracts\FirstFactorResolver;
use SineMacula\Laravel\Mfa\Contracts\SmsGateway;
use SineMacula\Laravel\Mfa\Database\StorageConnection;
use SineMacula\Laravel\Mfa\Drivers\TotpSettings;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentSettings;
use SineMacula\Laravel\Mfa\Exceptions\InvalidConfigurationException;
use SineMacula\Laravel\Mfa\Exceptions\InvalidFactorModelException;
use SineMacula\Laravel\Mfa\Factors\FactorService;
use SineMacula\Laravel\Mfa\Lifecycle\LifecycleSettings;
use SineMacula\Laravel\Mfa\Proofs\ProofSettings;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeSettings;

/**
 * Checks the whole configuration, and the bindings it needs, before anything
 * relies on it: every setting within its bounds, and every configured
 * application with a delivery binding for each code type it enables and a first
 * factor it declares or a bound `FirstFactorResolver` reports.
 *
 * Every check runs, so one run finds every problem. They are grouped by
 * subject: `storage`, `factor`, `identity_state`, one per capability block
 * (`totp`, `codes`, `recovery_codes`, `attempts`, `enrollment`, `proofs`,
 * `lifecycle`), `applications`, and `applications.{name}` for each configured
 * application. The package runs it once the application has booted and again
 * when the `mfa` manager is resolved, throwing an
 * `InvalidConfigurationException` that lists every problem; `mfa:check` prints
 * them instead. It reads configuration and the container only, and opens no
 * database connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ConfigurationValidator
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** The container the bindings are checked in. */
        private Container $container,

        /** The configuration that is checked. */
        private Repository $config,
    ) {}

    /**
     * Every subject's problems, an empty list for a subject without one.
     *
     * @return array<string, list<string>>
     */
    public function report(): array
    {
        $report = [];

        foreach ($this->checks() as $subject => $checks) {
            $problems = array_map(static fn (\Closure $check): ?string => self::problem($check), $checks);

            $report[$subject] = array_values(array_unique(array_filter($problems, static fn (?string $problem): bool => $problem !== null)));
        }

        return $report;
    }

    /**
     * Throw when any subject has a problem, listing every one.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\InvalidConfigurationException
     */
    public function validate(): void
    {
        $problems = [];

        foreach ($this->report() as $subject => $found) {

            foreach ($found as $problem) {
                $problems[] = sprintf('[%s] %s', $subject, $problem);
            }
        }

        if ($problems !== []) {
            throw new InvalidConfigurationException($problems);
        }
    }

    /**
     * The checks, by subject: each throws when it finds a problem.
     *
     * @return array<string, list<\Closure(): mixed>>
     */
    private function checks(): array
    {
        $config = $this->config;

        $checks = [
            'storage'        => [fn () => $this->checkStorageConnection()],
            'factor'         => [fn () => $this->checkFactorModel(), static fn () => self::checkTable($config, 'mfa.factor.table')],
            'identity_state' => [static fn () => self::checkTable($config, 'mfa.identity_state.table')],
            'totp'           => [static fn () => (new TotpSettings($config))->validate()],
            'codes'          => [static fn () => (new CodeSettings($config))->validate()],
            'recovery_codes' => [static fn () => (new RecoveryCodeSettings($config))->validate()],
            'attempts'       => [static fn () => (new AttemptSettings($config))->validate()],
            'enrollment'     => [static fn () => (new EnrollmentSettings($config))->validate()],
            'proofs'         => [static fn () => (new ProofSettings($config))->validate()],
            'lifecycle'      => [static fn () => (new LifecycleSettings($config))->validate()],
            'applications'   => [static fn () => ApplicationSettings::names($config)],
        ];

        try {
            $names = ApplicationSettings::names($config);
        } catch (\InvalidArgumentException) {
            return $checks;
        }

        foreach ($names as $name) {

            $application = new ApplicationSettings($config, $name);

            $checks['applications.' . $name] = [
                static fn () => $application->validate(),
                fn () => $this->checkDelivery($application),
                fn () => $this->checkFirstFactor($application),
            ];
        }

        return $checks;
    }

    /**
     * Refuse a storage connection that is malformed or that
     * `database.connections` does not configure; `null`, the default
     * connection, always is.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private function checkStorageConnection(): void
    {
        $connection  = StorageConnection::name();
        $connections = $this->config->get('database.connections');

        if ($connection !== null && !is_array($connections[$connection] ?? null)) {
            throw new \InvalidArgumentException(sprintf('mfa.storage.connection names [%s], which database.connections does not configure.', $connection));
        }
    }

    /**
     * Refuse a factor model that is not one, or that lives on another
     * connection than the storage one.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\InvalidFactorModelException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\ModelOffStorageConnectionException
     */
    private function checkFactorModel(): void
    {
        $model = $this->container->make(FactorService::class)->factorModel();

        StorageConnection::assertHolds(new $model, 'mfa.factor.model');
    }

    /**
     * Refuse a table name that is not a non-blank string.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  string  $key
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function checkTable(Repository $config, string $key): void
    {
        $table = $config->get($key);

        if ($table !== null && (!is_string($table) || trim($table) === '')) {
            throw new \InvalidArgumentException(sprintf('%s must be a table name.', $key));
        }
    }

    /**
     * Refuse an application that enables a code type with nothing bound to
     * deliver its codes: `sms` with the package's `NullSmsGateway` still bound
     * as the `SmsGateway`, or `email` with no mailer that resolves.
     *
     * @param  \SineMacula\Laravel\Mfa\Applications\ApplicationSettings  $application
     * @return void
     *
     * @throws \LogicException
     */
    private function checkDelivery(ApplicationSettings $application): void
    {
        if ($application->enables('sms') && $this->container->make(SmsGateway::class) instanceof NullSmsGateway) {
            throw new \LogicException(sprintf('The application enables sms, but no SMS gateway is bound: bind your gateway to %s.', SmsGateway::class));
        }

        if (!$application->enables('email')) {
            return;
        }

        try {
            $this->container->make(Mailer::class);
        } catch (BindingResolutionException) {
            throw new \LogicException(sprintf('The application enables email, but no mailer is bound to %s.', Mailer::class));
        }
    }

    /**
     * Refuse an application that neither declares its first factor nor has a
     * `FirstFactorResolver` bound to report it: without one, no further factor
     * can be accepted after the sign-in and no level established.
     *
     * @param  \SineMacula\Laravel\Mfa\Applications\ApplicationSettings  $application
     * @return void
     *
     * @throws \LogicException
     */
    private function checkFirstFactor(ApplicationSettings $application): void
    {
        if ($application->firstFactor() === null && !$this->container->bound(FirstFactorResolver::class)) {
            throw new \LogicException(sprintf('The application declares no first_factor, and no %s is bound to report it.', FirstFactorResolver::class));
        }
    }

    /**
     * The problem a check finds, or `null` when it finds none.
     *
     * @param  \Closure(): mixed  $check
     * @return ?string
     */
    private static function problem(\Closure $check): ?string
    {
        try {
            $check();
        } catch (InvalidFactorModelException|\LogicException $exception) {
            return $exception->getMessage();
        }

        return null;
    }
}
