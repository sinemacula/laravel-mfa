<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Config;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\BindingResolutionException;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Mfa\Applications\ApplicationSettings;
use SineMacula\Laravel\Mfa\Attempts\AttemptSettings;
use SineMacula\Laravel\Mfa\Codes\CodeKeys;
use SineMacula\Laravel\Mfa\Codes\CodeSettings;
use SineMacula\Laravel\Mfa\Codes\NullEmailSender;
use SineMacula\Laravel\Mfa\Codes\NullSmsSender;
use SineMacula\Laravel\Mfa\Contracts\EmailSender;
use SineMacula\Laravel\Mfa\Contracts\FirstFactorResolver;
use SineMacula\Laravel\Mfa\Contracts\SmsSender;
use SineMacula\Laravel\Mfa\Database\ConfiguredModels;
use SineMacula\Laravel\Mfa\Database\StorageConnection;
use SineMacula\Laravel\Mfa\Database\TableNames;
use SineMacula\Laravel\Mfa\Drivers\TotpSettings;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentSettings;
use SineMacula\Laravel\Mfa\Exceptions\InvalidConfigurationException;
use SineMacula\Laravel\Mfa\Exceptions\InvalidModelException;
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
 * subject: `storage` (the connection, and a name of its own for every table),
 * `factor`, `identity_state`, one per capability block (`totp`, `codes`,
 * `recovery_codes`, `attempts`, `enrollment`, `passkeys`, `proofs`,
 * `lifecycle`), `applications`, and `applications.{name}` for each configured
 * application. A block that names a table or a model has them checked with it:
 * a table name must be a non-blank string, and a model must be one, on the
 * storage connection. The package runs it once the application has booted and
 * again when the `mfa` manager is resolved, throwing an
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
            'storage'        => [fn () => $this->checkStorageConnection(), fn () => $this->checkDistinctTables()],
            'factor'         => [fn () => $this->checkModel(ConfiguredModels::factor($config), ConfiguredModels::FACTOR), fn () => $this->checkTable(TableNames::FACTORS)],
            'identity_state' => [fn () => $this->checkTable(TableNames::IDENTITY_STATES)],
            'totp'           => [static fn () => (new TotpSettings($config))->validate()],
            'codes'          => [static fn () => (new CodeSettings($config))->validate(), fn () => $this->checkTable(TableNames::CODES)],
            'recovery_codes' => [
                static fn () => (new RecoveryCodeSettings($config))->validate(),
                fn () => $this->checkModel(ConfiguredModels::recoveryCode($config), ConfiguredModels::RECOVERY_CODE),
                fn () => $this->checkTable(TableNames::RECOVERY_CODES),
            ],
            'attempts'     => [static fn () => (new AttemptSettings($config))->validate(), fn () => $this->checkTable(TableNames::ATTEMPTS)],
            'enrollment'   => [static fn () => (new EnrollmentSettings($config))->validate(), fn () => $this->checkTable(TableNames::ENROLLMENTS)],
            'passkeys'     => [fn () => $this->checkTable(TableNames::PASSKEY_ASSOCIATIONS)],
            'proofs'       => [static fn () => (new ProofSettings($config))->validate()],
            'lifecycle'    => [static fn () => (new LifecycleSettings($config))->validate()],
            'applications' => [static fn () => ApplicationSettings::names($config)],
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
     * Refuse a model that lives on another connection than the storage one.
     *
     * @param  class-string<\Illuminate\Database\Eloquent\Model>  $model
     * @param  string  $setting
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\ModelOffStorageConnectionException
     */
    private function checkModel(string $model, string $setting): void
    {
        StorageConnection::assertHolds(new $model, $setting);
    }

    /**
     * Refuse a table name that is not a non-blank string.
     *
     * @param  string  $block
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private function checkTable(string $block): void
    {
        $setting = TableNames::setting($block);
        $table   = $this->config->get($setting);

        if ($table !== null && (!is_string($table) || trim($table) === '')) {
            throw new \InvalidArgumentException(sprintf('%s must be a table name.', $setting));
        }
    }

    /**
     * Refuse two of the package's tables configured with the same name, which
     * the second migration would refuse to create.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private function checkDistinctTables(): void
    {
        $names = [];

        foreach (array_keys(TableNames::DEFAULTS) as $block) {
            $names[TableNames::setting($block)] = TableNames::of($block);
        }

        $shared = array_keys(array_filter(array_count_values($names), static fn (int $count): bool => $count > 1));

        if ($shared !== []) {
            $settings = array_keys(array_filter($names, static fn (string $name): bool => in_array($name, $shared, true)));

            throw new \InvalidArgumentException(sprintf('Each of the package\'s tables needs a name of its own: %s share one.', implode(', ', $settings)));
        }
    }

    /**
     * Refuse an application that enables a code type with nothing bound to
     * deliver its codes: `sms` with the package's `NullSmsSender` still bound
     * as the `SmsSender`, or `email` with its `NullEmailSender` still bound as
     * the `EmailSender`; and one that enables either while no application key
     * is set to hash its codes with.
     *
     * @param  \SineMacula\Laravel\Mfa\Applications\ApplicationSettings  $application
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
     */
    private function checkDelivery(ApplicationSettings $application): void
    {
        $sms   = $application->enables('sms');
        $email = $application->enables('email');

        if ($sms && $this->container->make(SmsSender::class) instanceof NullSmsSender) {
            throw new \LogicException(sprintf('The application enables sms, but no SMS sender is bound: bind yours to %s.', SmsSender::class));
        }

        if ($email && $this->container->make(EmailSender::class) instanceof NullEmailSender) {
            throw new \LogicException(sprintf('The application enables email, but no email sender is bound: bind yours, or the package\'s MailEmailSender, to %s.', EmailSender::class));
        }

        if ($sms || $email) {
            (new CodeKeys($this->config))->validate();
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
     * The problem a check finds, or `null` when it finds none. A binding the
     * container cannot build is a problem of the subject that needs it.
     *
     * @param  \Closure(): mixed  $check
     * @return ?string
     */
    private static function problem(\Closure $check): ?string
    {
        try {
            $check();
        } catch (BindingResolutionException|InvalidModelException|\LogicException $exception) {
            return $exception->getMessage();
        }

        return null;
    }
}
