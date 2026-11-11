<?php

declare(strict_types = 1);

namespace Tests\Unit\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Config;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Enums\EnrollmentAuthorization;
use SineMacula\Laravel\Mfa\Models\Code;
use SineMacula\Laravel\Mfa\Models\Enrollment;
use SineMacula\Laravel\Mfa\Models\IdentityState;
use SineMacula\Laravel\Mfa\Models\PasskeyAssociation;
use SineMacula\Laravel\Mfa\Models\RecoveryCode;
use Tests\TestCase;

/**
 * Enrolments, delivered codes, identity states, passkey associations and
 * recovery codes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Enrollment::class)]
#[CoversClass(Code::class)]
#[CoversClass(IdentityState::class)]
#[CoversClass(PasskeyAssociation::class)]
#[CoversClass(RecoveryCode::class)]
final class StoredRecordModelsTest extends TestCase
{
    /**
     * @return iterable<string, array{class-string<\Illuminate\Database\Eloquent\Model>, string, string}>
     */
    public static function tables(): iterable
    {
        foreach (self::records() as $name => [$model, $setting, $default]) {
            yield $name => [$model, $setting, $default];
        }
    }

    /**
     * @param  class-string<\Illuminate\Database\Eloquent\Model>  $model
     * @param  string  $setting
     * @param  string  $default
     * @return void
     */
    #[DataProvider('tables')]
    public function testTakesTheConfiguredTable(string $model, string $setting, string $default): void
    {
        self::assertSame($default, (new $model)->getTable());

        Config::set($setting, 'custom_records');

        try {
            self::assertSame('custom_records', (new $model)->getTable());
        } finally {
            Config::set($setting, null);
        }
    }

    /**
     * @return iterable<string, array{class-string<\Illuminate\Database\Eloquent\Model>}>
     */
    public static function models(): iterable
    {
        foreach (self::records() as $name => [$model]) {
            yield $name => [$model];
        }
    }

    /**
     * Named even when it is the default one.
     *
     * @param  class-string<\Illuminate\Database\Eloquent\Model>  $model
     * @return void
     */
    #[DataProvider('models')]
    public function testTakesTheStorageConnection(string $model): void
    {
        self::assertSame('testing', (new $model)->getConnectionName());

        Config::set('mfa.storage.connection', 'secondary');

        try {
            self::assertSame('secondary', (new $model)->getConnectionName());
        } finally {
            Config::set('mfa.storage.connection', null);
        }
    }

    /**
     * @param  class-string<\Illuminate\Database\Eloquent\Model>  $model
     * @return void
     */
    #[DataProvider('models')]
    public function testIsKeyedByAUlid(string $model): void
    {
        $instance = new $model;

        self::assertSame(['id'], $instance->uniqueIds());
        self::assertFalse($instance->getIncrementing());
    }

    /**
     * @return iterable<string, array{class-string<\Illuminate\Database\Eloquent\Model>, list<string>}>
     */
    public static function hidden(): iterable
    {
        foreach (self::records() as $name => [$model, , , $hidden]) {
            yield $name => [$model, $hidden];
        }
    }

    /**
     * @param  class-string<\Illuminate\Database\Eloquent\Model>  $model
     * @param  list<string>  $hidden
     * @return void
     */
    #[DataProvider('hidden')]
    public function testHidesWhatItMustNeverSerialize(string $model, array $hidden): void
    {
        self::assertSame($hidden, (new $model)->getHidden());
    }

    /**
     * @return iterable<string, array{class-string<\Illuminate\Database\Eloquent\Model>, array<string, string>}>
     */
    public static function casts(): iterable
    {
        foreach (self::records() as $name => [$model, , , , $casts]) {
            yield $name => [$model, $casts];
        }
    }

    /**
     * @param  class-string<\Illuminate\Database\Eloquent\Model>  $model
     * @param  array<string, string>  $casts
     * @return void
     */
    #[DataProvider('casts')]
    public function testCastsItsColumns(string $model, array $casts): void
    {
        $instance = new $model;

        foreach ($casts as $column => $cast) {
            self::assertTrue($instance->hasCast($column, $cast), $column);
        }
    }

    /**
     * @return void
     */
    public function testEveryColumnButTheKeyAndTimestampsIsFillable(): void
    {
        $owner = ['authenticatable_type', 'authenticatable_id'];

        self::assertSame(
            ['factor_id', ...$owner, 'grant_hash', 'application', 'session_id', 'generation', 'authority', 'challenge_id', 'expires_at', 'attempts'],
            (new Enrollment)->getFillable(),
        );
        self::assertSame(
            [
                'factor_id',
                ...$owner,
                'purpose',
                'application',
                'session_id',
                'destination_hash',
                'code_hash',
                'attempts',
                'sends',
                'sent_at',
                'sent_times',
                'expires_at',
                'consumed_at',
            ],
            (new Code)->getFillable(),
        );
        self::assertSame(
            [...$owner, 'verification_generation', 'reenrollment_required', 'consecutive_failures', 'locked_until', 'recovery_codes_generation', 'recovery_codes_generated_at'],
            (new IdentityState)->getFillable(),
        );
        self::assertSame(['factor_id', ...$owner, 'credential_id_hash', 'credential_id'], (new PasskeyAssociation)->getFillable());
        self::assertSame([...$owner, 'code_hash', 'generation', 'used_at', 'replaced_at'], (new RecoveryCode)->getFillable());
    }

    /**
     * So a model off the storage connection is refused rather than silently
     * moved.
     *
     * @return void
     */
    public function testARecoveryCodeSubclassKeepsItsOwnConnection(): void
    {
        $model = new class extends RecoveryCode {
            /** @var string|\UnitEnum|null */
            protected $connection = 'secondary';
        };

        self::assertSame('secondary', $model->getConnectionName());
        self::assertInstanceOf(Model::class, $model);
    }

    /**
     * @return iterable<string, array{class-string<\Illuminate\Database\Eloquent\Model>, string, string, list<string>, array<string, string>}>
     */
    private static function records(): iterable
    {
        yield 'enrolment' => [Enrollment::class, 'mfa.enrollment.table', 'mfa_enrollments', ['grant_hash', 'session_id'], [
            'authenticatable_type' => 'string',
            'authenticatable_id'   => 'string',
            'generation'           => 'integer',
            'authority'            => EnrollmentAuthorization::class,
            'expires_at'           => 'datetime',
            'attempts'             => 'integer',
        ]];
        yield 'code' => [Code::class, 'mfa.codes.table', 'mfa_codes', ['code_hash', 'session_id', 'destination_hash'], [
            'authenticatable_type' => 'string',
            'authenticatable_id'   => 'string',
            'attempts'             => 'integer',
            'sends'                => 'integer',
            'sent_at'              => 'datetime',
            'sent_times'           => 'array',
            'expires_at'           => 'datetime',
            'consumed_at'          => 'datetime',
        ]];
        yield 'identity state' => [IdentityState::class, 'mfa.identity_state.table', 'mfa_identity_states', [], [
            'authenticatable_type'        => 'string',
            'authenticatable_id'          => 'string',
            'verification_generation'     => 'integer',
            'reenrollment_required'       => 'boolean',
            'consecutive_failures'        => 'integer',
            'locked_until'                => 'datetime',
            'recovery_codes_generation'   => 'integer',
            'recovery_codes_generated_at' => 'datetime',
        ]];
        yield 'passkey association' => [PasskeyAssociation::class, 'mfa.passkeys.table', 'mfa_passkey_associations', [], [
            'authenticatable_type' => 'string',
            'authenticatable_id'   => 'string',
        ]];
        yield 'recovery code' => [RecoveryCode::class, 'mfa.recovery_codes.table', 'mfa_recovery_codes', ['code_hash'], [
            'authenticatable_type' => 'string',
            'authenticatable_id'   => 'string',
            'code_hash'            => 'string',
            'generation'           => 'integer',
            'used_at'              => 'datetime',
            'replaced_at'          => 'datetime',
        ]];
    }
}
