<?php

declare(strict_types = 1);

namespace Tests\Unit\Models;

use Illuminate\Database\Eloquent\Relations\MorphTo;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Config;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\TestUser;
use Tests\TestCase;

/**
 * Integration-leaning unit tests for the shipped `Factor` Eloquent model.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class FactorTest extends TestCase
{
    use RefreshDatabase;

    public function testImplementsEloquentFactorContract(): void
    {
        self::assertInstanceOf(EloquentFactor::class, new Factor);
    }

    public function testDefaultTableNameIsMfaFactors(): void
    {
        $factor = new Factor;

        self::assertSame('mfa_factors', $factor->getTable());
    }

    public function testTableNameFallsBackToDefaultWhenConfigFacadeIsNotBootstrapped(): void
    {
        // Swap out the bound Facade application so `Config::string(...)`
        // throws, exercising the defensive fallback in `resolveConfiguredTable`.
        $previous = \Illuminate\Support\Facades\Facade::getFacadeApplication();

        \Illuminate\Support\Facades\Facade::setFacadeApplication(null); // @phpstan-ignore argument.type
        \Illuminate\Support\Facades\Facade::clearResolvedInstance('config');

        try {
            $factor = new Factor;

            self::assertSame('mfa_factors', $factor->getTable());
        } finally {
            \Illuminate\Support\Facades\Facade::setFacadeApplication($previous);
        }
    }

    public function testTableNameResolvesFromConfig(): void
    {
        Config::set('mfa.factor.table', 'custom_factors');

        $factor = new Factor;

        self::assertSame('custom_factors', $factor->getTable());
    }

    public function testTableNameFallsBackToDefaultWhenConfigIsEmpty(): void
    {
        Config::set('mfa.factor.table', '');

        $factor = new Factor;

        self::assertSame('mfa_factors', $factor->getTable());
    }

    public function testUniqueIdsReturnsIdColumn(): void
    {
        self::assertSame(['id'], (new Factor)->uniqueIds());
    }

    public function testGeneratesUlidPrimaryKeyOnSave(): void
    {
        $user = TestUser::create(['email' => 'alice@example.com', 'mfa_enabled' => true]);

        $factor = new Factor([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->getKey(),
            'driver'               => 'email',
        ]);
        $factor->save();

        self::assertIsString($factor->id);
        self::assertNotSame('', $factor->id);
        self::assertSame(26, strlen($factor->id));
    }

    public function testAuthenticatableMorphToRelation(): void
    {
        $user = TestUser::create(['email' => 'alice@example.com', 'mfa_enabled' => true]);

        $factor = new Factor([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->getKey(),
            'driver'               => 'totp',
        ]);
        $factor->save();

        $relation = $factor->authenticatable();

        self::assertInstanceOf(MorphTo::class, $relation);

        /** @var ?\Tests\Fixtures\TestUser $loaded */
        $loaded = $factor->authenticatable()->getResults();

        self::assertInstanceOf(TestUser::class, $loaded);
        self::assertSame($user->getKey(), $loaded->getKey());
    }

    public function testSecretIsEncryptedAtRestAndDecryptsOnRead(): void
    {
        $user = TestUser::create(['email' => 'alice@example.com', 'mfa_enabled' => true]);

        $factor = new Factor([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->getKey(),
            'driver'               => 'totp',
            'secret'               => 'JBSWY3DPEHPK3PXP',
        ]);
        $factor->save();

        // Reload from DB to ensure encryption round-trips.
        $reloaded = Factor::query()->findOrFail($factor->id);

        self::assertSame('JBSWY3DPEHPK3PXP', $reloaded->secret);

        // Inspect the raw DB row to confirm the value is not stored as
        // plaintext.
        $connection = $factor->getConnection();

        /** @var object{secret: ?string} $raw */
        $raw = $connection->table($factor->getTable())
            ->where('id', $factor->id)
            ->first(['secret']);

        self::assertNotNull($raw->secret);
        self::assertNotSame('JBSWY3DPEHPK3PXP', $raw->secret);
    }

    public function testSecretAndCodeAreHiddenFromSerialisation(): void
    {
        $user = TestUser::create(['email' => 'alice@example.com', 'mfa_enabled' => true]);

        $factor = new Factor([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->getKey(),
            'driver'               => 'email',
            'secret'               => 'super-secret',
            'code'                 => '654321',
        ]);
        $factor->save();

        $array = $factor->toArray();

        self::assertArrayNotHasKey('secret', $array);
        self::assertArrayNotHasKey('code', $array);
        self::assertArrayHasKey('driver', $array);
    }
}
