<?php

declare(strict_types = 1);

namespace Tests\Unit\Database;

use Illuminate\Config\Repository;
use Illuminate\Database\Eloquent\Model;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Concerns\ActsAsRecoveryCode;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\RecoveryCode as RecoveryCodeContract;
use SineMacula\Laravel\Mfa\Database\ConfiguredModels;
use SineMacula\Laravel\Mfa\Exceptions\InvalidModelException;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Models\RecoveryCode;
use Tests\Fixtures\Factors\CustomFactor;
use Tests\Fixtures\RecoveryCodes\SecondaryConnectionRecoveryCode;

/**
 * Unit tests for `ConfiguredModels`: the factor and recovery code models an
 * application may replace, and the settings it refuses.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConfiguredModels::class)]
#[CoversClass(InvalidModelException::class)]
final class ConfiguredModelsTest extends TestCase
{
    /**
     * With nothing configured, the shipped models.
     *
     * @return void
     */
    public function testWithNothingConfiguredTheShippedModels(): void
    {
        $config = new Repository;

        self::assertSame(Factor::class, ConfiguredModels::factor($config));
        self::assertSame(RecoveryCode::class, ConfiguredModels::recoveryCode($config));
    }

    /**
     * A configured subclass is taken.
     *
     * @return void
     */
    public function testAConfiguredSubclassIsTaken(): void
    {
        $config = new Repository(['mfa' => [
            'factor'         => ['model' => CustomFactor::class],
            'recovery_codes' => ['model' => SecondaryConnectionRecoveryCode::class],
        ]]);

        self::assertSame(CustomFactor::class, ConfiguredModels::factor($config));
        self::assertSame(SecondaryConnectionRecoveryCode::class, ConfiguredModels::recoveryCode($config));
    }

    /**
     * Rows of a setting, a value it refuses and the problem.
     *
     * @return iterable<string, array{string, mixed, string}>
     */
    public static function refused(): iterable
    {
        yield 'a factor model that is not a string' => ['factor', 5, 'mfa.factor.model must be a class string; got [int].'];
        yield 'a blank factor model' => ['factor', '', 'mfa.factor.model must be a class string; got [string].'];
        yield 'a factor model that does not exist' => ['factor', 'App\Missing', 'mfa.factor.model class [App\Missing] does not exist.'];
        yield 'a factor model that is not a factor' => [
            'factor',
            RecoveryCode::class,
            sprintf('mfa.factor.model class [%s] must extend %s and implement %s.', RecoveryCode::class, Model::class, EloquentFactor::class),
        ];
        yield 'a recovery code model that is not a model' => [
            'recovery_codes',
            \stdClass::class,
            sprintf('mfa.recovery_codes.model class [stdClass] must extend %s and implement %s.', Model::class, RecoveryCodeContract::class),
        ];
        yield 'a recovery code model that is a factor' => [
            'recovery_codes',
            Factor::class,
            sprintf('mfa.recovery_codes.model class [%s] must extend %s and implement %s.', Factor::class, Model::class, RecoveryCodeContract::class),
        ];
    }

    /**
     * A setting that names no model implementing the contract is refused.
     *
     * @param  string  $block
     * @param  mixed  $value
     * @param  string  $problem
     * @return void
     */
    #[DataProvider('refused')]
    public function testASettingThatNamesNoSuchModelIsRefused(string $block, mixed $value, string $problem): void
    {
        $config = new Repository(['mfa' => [$block => ['model' => $value]]]);

        $this->expectException(InvalidModelException::class);
        $this->expectExceptionMessage($problem);

        $block === 'factor' ? ConfiguredModels::factor($config) : ConfiguredModels::recoveryCode($config);
    }

    /**
     * A contract implementation that is not an Eloquent model is refused.
     *
     * @return void
     */
    public function testAContractImplementationThatIsNotAModelIsRefused(): void
    {
        $implementation = new class implements RecoveryCodeContract {
            use ActsAsRecoveryCode;
        };

        $config = new Repository(['mfa' => ['recovery_codes' => ['model' => $implementation::class]]]);

        $this->expectException(InvalidModelException::class);

        ConfiguredModels::recoveryCode($config);
    }
}
