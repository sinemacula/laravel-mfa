<?php

declare(strict_types = 1);

namespace Tests\Unit\Applications;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Applications\ApplicationBlock;
use SineMacula\Laravel\Mfa\Applications\ApplicationSettings;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\RequirementMode;
use SineMacula\Laravel\Mfa\Enums\RequirementPart;
use SineMacula\Laravel\Mfa\Requirements\Requirement;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ApplicationSettings::class)]
#[CoversClass(ApplicationBlock::class)]
final class ApplicationSettingsTest extends TestCase
{
    /** @var string The application the tests configure. */
    private const string APPLICATION = 'web';

    /** @var string The prefix of every key of the application the tests configure. */
    private const string KEY = 'mfa.applications.web.';

    /** @var array<string, array<string, int>> The serialised requirement each of the package's own operations has by default. */
    private const array FIFTEEN_MINUTES = ['additional_verification' => ['max_age' => 900]];

    /**
     * In order; none when the block is missing or empty.
     *
     * @return void
     */
    public function testNamesListTheConfiguredApplications(): void
    {
        self::assertSame([], ApplicationSettings::names(new Repository));
        self::assertSame([], ApplicationSettings::names(new Repository(['mfa' => ['applications' => null]])));
        self::assertSame(['web', 'admin.panel'], ApplicationSettings::names(self::config(['web' => [], 'admin.panel' => []])));
    }

    /**
     * @return iterable<string, array{mixed, string}>
     */
    public static function malformedApplications(): iterable
    {
        yield 'not an array' => ['web', 'mfa.applications must be an array of application blocks keyed by name.'];
        yield 'a list' => [[[]], 'mfa.applications must be keyed by application name.'];
        yield 'a blank name' => [[' ' => []], 'mfa.applications must be keyed by application name.'];
    }

    /**
     * @param  mixed  $applications
     * @param  string  $message
     * @return void
     */
    #[DataProvider('malformedApplications')]
    public function testNamesRefuseApplicationsNotKeyedByName(mixed $applications, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        ApplicationSettings::names(new Repository(['mfa' => ['applications' => $applications]]));
    }

    /**
     * No type, requirement, recovery codes, bootstrap or first factor; the
     * default limits, and the package's TOTP window and freshness.
     *
     * @return void
     */
    public function testAnUnconfiguredApplicationTakesTheDefaults(): void
    {
        $settings = new ApplicationSettings(new Repository, 'unknown');

        self::assertSame([], $settings->types());
        self::assertFalse($settings->enables('totp'));
        self::assertSame(RequirementMode::NEVER, $settings->requirement());
        self::assertFalse($settings->acceptsRecoveryCodes());
        self::assertSame(AssuranceLevel::AAL2, $settings->recoveryCodeLevel());
        self::assertFalse($settings->allowsBootstrap());
        self::assertSame([], $settings->bootstrapTypes());
        self::assertSame(5, $settings->confirmedPerTypeLimit());
        self::assertSame(10, $settings->confirmedLimit());
        self::assertSame(2, $settings->pendingLimit());
        self::assertSame(1, $settings->totpWindow());
        self::assertSame([
            'mfa.add_factor'              => self::FIFTEEN_MINUTES,
            'mfa.replace_factor'          => self::FIFTEEN_MINUTES,
            'mfa.remove_factor'           => self::FIFTEEN_MINUTES,
            'mfa.generate_recovery_codes' => self::FIFTEEN_MINUTES,
        ], array_map(static fn (Requirement $requirement): array => $requirement->toArray(), $settings->freshness()));
        self::assertSame(self::FIFTEEN_MINUTES, $settings->freshnessFor('mfa.remove_factor')?->toArray());
        self::assertNull($settings->freshnessFor('billing.change_plan'));
        self::assertNull($settings->firstFactor());

        $settings->validate();
    }

    /**
     * Also under a name with a dot, and for every application while none are
     * configured.
     *
     * @return void
     */
    public function testAnEmptyBlockTakesTheDefaults(): void
    {
        self::assertSame(RequirementMode::NEVER, self::settings([])->requirement());
        self::assertSame(['sms'], (new ApplicationSettings(self::config(['admin.panel' => ['types' => ['sms']]]), 'admin.panel'))->types());
        self::assertSame([], (new ApplicationSettings(new Repository(['mfa' => ['applications' => null]]), self::APPLICATION))->types());
    }

    /**
     * By every reader, even one built before it was set, rather than defaulting
     * every application.
     *
     * @return void
     */
    public function testAMalformedApplicationsBlockIsRefusedWhenRead(): void
    {
        $config   = self::config([self::APPLICATION => ['types' => ['totp']]]);
        $settings = new ApplicationSettings($config, self::APPLICATION);

        self::assertSame(['totp'], $settings->types());

        $config->set(ApplicationSettings::APPLICATIONS, 'web');

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('mfa.applications must be an array of application blocks keyed by name.');

        $settings->types();
    }

    /**
     * A total limit below 5 lowers the unset per-type default instead of
     * failing it.
     *
     * @return void
     */
    public function testThePerTypeLimitDefaultFollowsALowerTotal(): void
    {
        $lower = self::settings(['limits' => ['confirmed' => 3]]);

        self::assertSame(3, $lower->confirmedPerTypeLimit());
        self::assertSame(5, self::settings(['limits' => ['confirmed' => 5]])->confirmedPerTypeLimit());
        self::assertSame(5, self::settings(['limits' => ['confirmed' => '6']])->confirmedPerTypeLimit());

        $lower->validate();
    }

    /**
     * @return void
     */
    public function testReadsEveryConfiguredSetting(): void
    {
        $settings = self::settings([
            'types'          => ['totp', 'sms'],
            'requirement'    => 'always',
            'recovery_codes' => ['enabled' => true, 'level' => 'aal3'],
            'bootstrap'      => ['enabled' => true, 'types' => ['totp', 'sms']],
            'limits'         => ['confirmed_per_type' => 2, 'confirmed' => 3, 'pending' => '4'],
            'totp_window'    => '0',
            'freshness'      => [
                'mfa.remove_factor'   => 60,
                'billing.change_plan' => '300',
                'reports.export'      => ['multifactor' => ['max_age' => 120], 'minimum_level' => ['level' => 'aal2', 'max_age' => 600]],
            ],
            'first_factor' => ['method' => 'password', 'channel' => 'password'],
        ]);

        self::assertSame(['totp', 'sms'], $settings->types());
        self::assertTrue($settings->enables('sms'));
        self::assertFalse($settings->enables('email'));
        self::assertSame(RequirementMode::ALWAYS, $settings->requirement());
        self::assertTrue($settings->acceptsRecoveryCodes());
        self::assertSame(AssuranceLevel::AAL3, $settings->recoveryCodeLevel());
        self::assertTrue($settings->allowsBootstrap());
        self::assertSame(['totp', 'sms'], $settings->bootstrapTypes());
        self::assertSame(2, $settings->confirmedPerTypeLimit());
        self::assertSame(3, $settings->confirmedLimit());
        self::assertSame(4, $settings->pendingLimit());
        self::assertSame(0, $settings->totpWindow());
        self::assertSame(['additional_verification' => ['max_age' => 60]], $settings->freshnessFor('mfa.remove_factor')?->toArray());
        self::assertSame(self::FIFTEEN_MINUTES, $settings->freshnessFor('mfa.add_factor')?->toArray());
        self::assertSame(['additional_verification' => ['max_age' => 300]], $settings->freshnessFor('billing.change_plan')?->toArray());
        self::assertSame(
            ['multifactor' => ['max_age' => 120], 'minimum_level' => ['level' => 'aal2', 'max_age' => 600]],
            $settings->freshnessFor('reports.export')?->toArray(),
        );

        $declared = $settings->firstFactor();

        self::assertNotNull($declared);
        self::assertSame('password', $declared->method);
        self::assertSame(ChannelKind::PASSWORD, $declared->channel);

        $settings->validate();
    }

    /**
     * The per-type limit may reach the total limit.
     *
     * @return void
     */
    public function testReadsTheBoundsOfEachNumber(): void
    {
        $least = self::settings(['limits' => ['confirmed_per_type' => 1, 'confirmed' => 1, 'pending' => 1], 'totp_window' => 0]);
        $most  = self::settings(['limits' => ['confirmed_per_type' => 50, 'confirmed' => 50, 'pending' => 10], 'totp_window' => 3]);

        self::assertSame([1, 1, 1, 0], [$least->confirmedPerTypeLimit(), $least->confirmedLimit(), $least->pendingLimit(), $least->totpWindow()]);
        self::assertSame([50, 50, 10, 3], [$most->confirmedPerTypeLimit(), $most->confirmedLimit(), $most->pendingLimit(), $most->totpWindow()]);
        self::assertSame(1, self::settings(['freshness' => ['mfa.add_factor' => 1]])->freshnessFor('mfa.add_factor')?->maxAge(RequirementPart::ADDITIONAL_VERIFICATION));
        self::assertSame(86400, self::settings(['freshness' => ['mfa.add_factor' => 86400]])->freshnessFor('mfa.add_factor')?->maxAge(RequirementPart::ADDITIONAL_VERIFICATION));
        $multifactor = self::settings(['freshness' => ['mfa.add_factor' => ['multifactor' => ['max_age' => 86400]]]]);

        self::assertSame(86400, $multifactor->freshnessFor('mfa.add_factor')?->maxAge(RequirementPart::MULTIFACTOR));
    }

    /**
     * @return void
     */
    public function testTheTotpWindowFallsBackToThePackageWindow(): void
    {
        $config = new Repository(['mfa' => ['applications' => ['web' => ['totp_window' => null]], 'totp' => ['window' => 2]]]);

        self::assertSame(2, (new ApplicationSettings($config, self::APPLICATION))->totpWindow());
    }

    /**
     * @return void
     */
    public function testEveryKnownChannelKindCanBeDeclared(): void
    {
        foreach (ChannelKind::cases() as $kind) {

            if ($kind === ChannelKind::UNKNOWN) {
                continue;
            }

            self::assertSame($kind, self::settings(['first_factor' => ['method' => 'sign_in', 'channel' => $kind->value]])->firstFactor()?->channel);
        }
    }

    /**
     * @return iterable<string, array{mixed, \Closure(\SineMacula\Laravel\Mfa\Applications\ApplicationSettings): mixed, string}>
     */
    public static function malformedSettings(): iterable
    {
        $types       = static fn (ApplicationSettings $settings): array => $settings->types();
        $requirement = static fn (ApplicationSettings $settings): RequirementMode => $settings->requirement();
        $recovery    = static fn (ApplicationSettings $settings): bool => $settings->acceptsRecoveryCodes();
        $level       = static fn (ApplicationSettings $settings): AssuranceLevel => $settings->recoveryCodeLevel();
        $bootstrap   = static fn (ApplicationSettings $settings): array => $settings->bootstrapTypes();
        $perType     = static fn (ApplicationSettings $settings): int => $settings->confirmedPerTypeLimit();
        $pending     = static fn (ApplicationSettings $settings): int => $settings->pendingLimit();
        $window      = static fn (ApplicationSettings $settings): int => $settings->totpWindow();
        $freshness   = static fn (ApplicationSettings $settings): array => $settings->freshness();
        $first       = static fn (ApplicationSettings $settings): mixed => $settings->firstFactor();

        $typeList  = self::KEY . 'types must be a list of distinct factor type names.';
        $declared  = self::KEY . 'first_factor must be null, or a method and the kind of channel it proves (any channel kind but unknown).';
        $fresh     = self::KEY . 'freshness must map operation names, such as mfa.add_factor, to seconds or requirements.';
        $unbounded = self::KEY . 'freshness.billing.change_plan must give every part a max_age from 1 to 86400 seconds, which its [multifactor] part does not.';
        $bootTypes = self::KEY . 'bootstrap.types must be a list of distinct factor type names.';

        yield 'a block that is not an array' => ['on', $types, 'mfa.applications.web must be an array.'];
        yield 'a key the block does not know' => [['type' => ['totp'], 'mode' => 'always'], $requirement, 'mfa.applications.web holds keys it does not know: type, mode.'];
        yield 'types that are not a list' => [['types' => 'totp'], $types, $typeList];
        yield 'types keyed by name' => [['types' => ['first' => 'totp']], $types, $typeList];
        yield 'a repeated type' => [['types' => ['totp', 'totp']], $types, $typeList];
        yield 'a type that is not a string' => [['types' => [1]], $types, $typeList];
        yield 'a blank type' => [['types' => ['totp', ' ']], $types, $typeList];
        yield 'an unknown requirement' => [['requirement' => 'sometimes'], $requirement, self::KEY . 'requirement must be one of never, enrolled, always.'];
        yield 'a requirement that is not a string' => [['requirement' => true], $requirement, self::KEY . 'requirement must be one of never, enrolled, always.'];
        yield 'a recovery block that is not an array' => [['recovery_codes' => true], $recovery, self::KEY . 'recovery_codes must be an array.'];
        yield 'a key the recovery block does not know' => [
            ['recovery_codes' => ['enabled' => true, 'count' => 5]],
            $recovery,
            self::KEY . 'recovery_codes holds keys it does not know: count.',
        ];
        yield 'a recovery flag that is not a boolean' => [['recovery_codes' => ['enabled' => 'yes']], $recovery, self::KEY . 'recovery_codes.enabled must be true or false.'];
        yield 'an unknown recovery level' => [['recovery_codes' => ['level' => 'aal4']], $level, self::KEY . 'recovery_codes.level must be one of aal1, aal2, aal3.'];
        yield 'an unclassified recovery level' => [['recovery_codes' => ['level' => 'unclassified']], $level, self::KEY . 'recovery_codes.level must be one of aal1, aal2, aal3.'];
        yield 'a recovery level that is not a string' => [['recovery_codes' => ['level' => 2]], $level, self::KEY . 'recovery_codes.level must be one of aal1, aal2, aal3.'];
        yield 'a bootstrap flag that is not a boolean' => [
            ['bootstrap' => ['enabled' => 1]],
            static fn (ApplicationSettings $settings): bool => $settings->allowsBootstrap(),
            self::KEY . 'bootstrap.enabled must be true or false.',
        ];
        yield 'a bootstrap flag that is not a boolean beside its types' => [
            ['types' => ['totp'], 'bootstrap' => ['enabled' => 'yes', 'types' => ['totp']]],
            $bootstrap,
            self::KEY . 'bootstrap.enabled must be true or false.',
        ];
        yield 'bootstrap types that are not a list' => [['types' => ['totp'], 'bootstrap' => ['types' => 'totp']], $bootstrap, $bootTypes];
        yield 'a bootstrap type the application does not enable' => [
            ['types' => ['totp'], 'bootstrap' => ['types' => ['totp', 'sms']]],
            $bootstrap,
            self::KEY . 'bootstrap.types must list only types the application enables in mfa.applications.web.types.',
        ];
        yield 'bootstrap enabled without a type' => [
            ['types' => ['totp'], 'bootstrap' => ['enabled' => true]],
            $bootstrap,
            self::KEY . 'bootstrap.types must list at least one type while bootstrap is enabled.',
        ];
        yield 'a limits block that is not an array' => [['limits' => 5], $pending, self::KEY . 'limits must be an array.'];
        yield 'a key the limits block does not know' => [['limits' => ['total' => 5]], $pending, self::KEY . 'limits holds keys it does not know: total.'];
        yield 'no pending enrolment allowed' => [['limits' => ['pending' => 0]], $pending, self::KEY . 'limits.pending must be an integer from 1 to 10.'];
        yield 'too many pending enrolments' => [['limits' => ['pending' => 11]], $pending, self::KEY . 'limits.pending must be an integer from 1 to 10.'];
        yield 'no confirmed factor allowed' => [['limits' => ['confirmed' => 0]], $perType, self::KEY . 'limits.confirmed must be an integer from 1 to 50.'];
        yield 'too many confirmed factors' => [['limits' => ['confirmed' => 51]], $perType, self::KEY . 'limits.confirmed must be an integer from 1 to 50.'];
        yield 'no factor of a type allowed' => [['limits' => ['confirmed_per_type' => 0]], $perType, self::KEY . 'limits.confirmed_per_type must be an integer from 1 to 10.'];
        yield 'more of one type than in total' => [
            ['limits' => ['confirmed_per_type' => 4, 'confirmed' => 3]],
            $perType,
            self::KEY . 'limits.confirmed_per_type must be an integer from 1 to 3.',
        ];
        yield 'a negative TOTP window' => [['totp_window' => -1], $window, self::KEY . 'totp_window must be an integer from 0 to 3.'];
        yield 'too wide a TOTP window' => [['totp_window' => 4], $window, self::KEY . 'totp_window must be an integer from 0 to 3.'];
        yield 'freshness that is not an array' => [['freshness' => 900], $freshness, $fresh];
        yield 'freshness keyed by position' => [['freshness' => [900]], $freshness, $fresh];
        yield 'freshness for a blank operation' => [['freshness' => [' ' => 900]], $freshness, $fresh];
        yield 'freshness for an operation in capitals' => [['freshness' => ['Billing.Change_Plan' => 900]], $freshness, $fresh];
        yield 'freshness for an operation with a trailing newline' => [['freshness' => ["billing.change_plan\n" => 900]], $freshness, $fresh];
        yield 'freshness that is neither seconds nor a requirement' => [
            ['freshness' => ['billing.change_plan' => true]],
            $freshness,
            self::KEY . 'freshness.billing.change_plan must be an integer from 1 to 86400.',
        ];
        yield 'freshness of a requirement with an unknown part' => [
            ['freshness' => ['billing.change_plan' => ['sometimes' => []]]],
            $freshness,
            self::KEY . 'freshness.billing.change_plan must be seconds or a serialised requirement: The [sometimes] part of a serialised requirement is not a known part.',
        ];
        yield 'freshness of a requirement asking for nothing' => [
            ['freshness' => ['billing.change_plan' => []]],
            $freshness,
            self::KEY . 'freshness.billing.change_plan must ask for at least one part.',
        ];
        yield 'freshness of a requirement with no maximum age' => [['freshness' => ['billing.change_plan' => ['multifactor' => []]]], $freshness, $unbounded];
        yield 'freshness of a requirement past a day' => [['freshness' => ['billing.change_plan' => ['multifactor' => ['max_age' => 86401]]]], $freshness, $unbounded];
        yield 'freshness of no time' => [['freshness' => ['mfa.add_factor' => 0]], $freshness, self::KEY . 'freshness.mfa.add_factor must be an integer from 1 to 86400.'];
        yield 'freshness past a day' => [
            ['freshness' => ['billing.change_plan' => 86401]],
            $freshness,
            self::KEY . 'freshness.billing.change_plan must be an integer from 1 to 86400.',
        ];
        yield 'a first factor that is not an array' => [['first_factor' => 'password'], $first, self::KEY . 'first_factor must be an array.'];
        yield 'a key the first factor does not know' => [
            ['first_factor' => ['method' => 'password', 'channel' => 'password', 'trusted' => true]],
            $first,
            self::KEY . 'first_factor holds keys it does not know: trusted.',
        ];
        yield 'an empty first factor' => [['first_factor' => []], $first, $declared];
        yield 'a first factor without a method' => [['first_factor' => ['channel' => 'password']], $first, $declared];
        yield 'a first factor with a blank method' => [['first_factor' => ['method' => ' ', 'channel' => 'password']], $first, $declared];
        yield 'a first factor without a channel' => [['first_factor' => ['method' => 'password']], $first, $declared];
        yield 'a first factor with a channel that is not a string' => [['first_factor' => ['method' => 'password', 'channel' => 1]], $first, $declared];
        yield 'a first factor with an unknown channel' => [['first_factor' => ['method' => 'password', 'channel' => 'pigeon']], $first, $declared];
        yield 'a first factor whose channel is unknown' => [['first_factor' => ['method' => 'password', 'channel' => 'unknown']], $first, $declared];
    }

    /**
     * Fails closed naming its key, both when read and when validated.
     *
     * @param  mixed  $block
     * @param  \Closure(\SineMacula\Laravel\Mfa\Applications\ApplicationSettings): mixed  $read
     * @param  string  $message
     * @return void
     */
    #[DataProvider('malformedSettings')]
    public function testAMalformedSettingIsRefused(mixed $block, \Closure $read, string $message): void
    {
        $settings = self::settings($block);

        foreach ([static fn (): mixed => $read($settings), static fn () => $settings->validate()] as $call) {

            try {
                $call();
                self::fail('Expected the setting to be refused.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame($message, $exception->getMessage());
            }
        }
    }

    /**
     * @param  mixed  $block
     * @return \SineMacula\Laravel\Mfa\Applications\ApplicationSettings
     */
    private static function settings(mixed $block): ApplicationSettings
    {
        return new ApplicationSettings(self::config([self::APPLICATION => $block]), self::APPLICATION);
    }

    /**
     * @param  array<string, mixed>  $applications
     * @return \Illuminate\Config\Repository
     */
    private static function config(array $applications): Repository
    {
        return new Repository(['mfa' => ['applications' => $applications]]);
    }
}
