<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Config;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\BindingResolutionException;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Mfa\Applications\ApplicationSettings;
use SineMacula\Laravel\Mfa\Applications\DeclaredFirstFactorResolver;
use SineMacula\Laravel\Mfa\Attempts\AttemptSettings;
use SineMacula\Laravel\Mfa\Codes\CodeKeys;
use SineMacula\Laravel\Mfa\Codes\CodeSettings;
use SineMacula\Laravel\Mfa\Codes\NullEmailSender;
use SineMacula\Laravel\Mfa\Codes\NullSmsSender;
use SineMacula\Laravel\Mfa\Contracts\EmailSender;
use SineMacula\Laravel\Mfa\Contracts\FirstFactorResolver;
use SineMacula\Laravel\Mfa\Contracts\PasskeyGateway;
use SineMacula\Laravel\Mfa\Contracts\SmsSender;
use SineMacula\Laravel\Mfa\Database\ConfiguredModels;
use SineMacula\Laravel\Mfa\Database\StorageConnection;
use SineMacula\Laravel\Mfa\Database\TableNames;
use SineMacula\Laravel\Mfa\Drivers\TotpSettings;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentSettings;
use SineMacula\Laravel\Mfa\Exceptions\InvalidConfigurationException;
use SineMacula\Laravel\Mfa\Exceptions\InvalidModelException;
use SineMacula\Laravel\Mfa\Lifecycle\LifecycleSettings;
use SineMacula\Laravel\Mfa\Passkeys\UnavailablePasskeyGateway;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeSettings;

/**
 * Checks the whole configuration and the bindings it needs. Every check runs,
 * so one run reports every problem. Opens no database connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ConfigurationValidator
{
    /**
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** Where the bindings are checked. */
        private Container $container,

        /** What is checked. */
        private Repository $config,
    ) {}

    /**
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
                fn () => $this->checkPasskeys($application),
                fn () => $this->checkFirstFactor($application),
            ];
        }

        return $checks;
    }

    /**
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
     * The second migration would refuse to create a shared table.
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
     * Refuse a code type with only the null sender bound, or with no `app.key`
     * to hash its codes.
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
            $message = 'The application enables email, but no email sender is bound: bind yours, or the package\'s MailEmailSender, to %s.';

            throw new \LogicException(sprintf($message, EmailSender::class));
        }

        if (!$sms && !$email) {
            return;
        }

        (new CodeKeys($this->config))->validate();
    }

    /**
     * A gateway that reports itself unavailable at run time is not refused; the
     * type is then never offered.
     *
     * @param  \SineMacula\Laravel\Mfa\Applications\ApplicationSettings  $application
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
     */
    private function checkPasskeys(ApplicationSettings $application): void
    {
        if (!$application->enables('passkey')) {
            return;
        }

        self::checkPasskeyGateway($this->container->make(PasskeyGateway::class));
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\PasskeyGateway  $gateway
     * @return void
     *
     * @throws \LogicException
     */
    private static function checkPasskeyGateway(PasskeyGateway $gateway): void
    {
        if ($gateway instanceof UnavailablePasskeyGateway) {
            throw new \LogicException(sprintf('The application enables passkey, but no passkey gateway is bound: bind yours to %s.', PasskeyGateway::class));
        }
    }

    /**
     * Without a declaration or a resolver of its own, no further factor can be
     * accepted and no level established.
     *
     * @param  \SineMacula\Laravel\Mfa\Applications\ApplicationSettings  $application
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
     */
    private function checkFirstFactor(ApplicationSettings $application): void
    {
        if ($application->firstFactor() !== null) {
            return;
        }

        if (!$this->container->bound(FirstFactorResolver::class) || $this->container->make(FirstFactorResolver::class) instanceof DeclaredFirstFactorResolver) {
            throw new \LogicException(sprintf('The application declares no first_factor, and no %s is bound to report it.', FirstFactorResolver::class));
        }
    }

    /**
     * A binding the container cannot build is the subject's problem.
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
