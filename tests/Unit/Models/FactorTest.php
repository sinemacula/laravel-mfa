<?php

declare(strict_types = 1);

namespace Tests\Unit\Models;

use Illuminate\Database\Eloquent\Relations\MorphTo;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Facade;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\Factors\SecondaryConnectionFactor;
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Factor::class)]
final class FactorTest extends TestCase
{
    use RefreshDatabase;

    /** @var string */
    private const string TEST_USER_EMAIL = 'alice@example.com';

    /**
     * @return void
     */
    public function testImplementsEloquentFactorContract(): void
    {
        self::assertInstanceOf(EloquentFactor::class, new Factor);
    }

    /**
     * @return void
     */
    public function testDefaultTableNameIsMfaFactors(): void
    {
        $factor = new Factor;

        self::assertSame('mfa_factors', $factor->getTable());
    }

    /**
     * @return void
     */
    public function testTableNameFallsBackToDefaultWhenConfigFacadeIsNotBootstrapped(): void
    {
        // Make `Config::string()` throw to reach the fallback in
        // `resolveConfiguredTable`.
        $previous = Facade::getFacadeApplication();

        // The upstream stub claims non-null, but tear-down accepts null.
        // @phpstan-ignore argument.type
        Facade::setFacadeApplication(null);
        Facade::clearResolvedInstance('config');

        try {
            $factor = new Factor;
            self::assertSame('mfa_factors', $factor->getTable());
            self::assertNull($factor->getConnectionName());
        } finally {
            Facade::setFacadeApplication($previous);
        }
    }

    /**
     * @return void
     */
    public function testTableNameResolvesFromConfig(): void
    {
        Config::set('mfa.factor.table', 'custom_factors');

        $factor = new Factor;

        self::assertSame('custom_factors', $factor->getTable());
    }

    /**
     * @return void
     */
    public function testTableNameFallsBackToDefaultWhenConfigIsEmpty(): void
    {
        Config::set('mfa.factor.table', '');

        $factor = new Factor;

        self::assertSame('mfa_factors', $factor->getTable());
    }

    /**
     * Named even when it is the default one.
     *
     * @return void
     */
    public function testTakesTheStorageConnection(): void
    {
        self::assertSame('testing', (new Factor)->getConnectionName());

        Config::set('mfa.storage.connection', 'secondary');

        self::assertSame('secondary', (new Factor)->getConnectionName());

        Config::set('mfa.storage.connection', null);
    }

    /**
     * So a model off the storage connection is refused rather than silently
     * moved.
     *
     * @return void
     */
    public function testKeepsAConnectionTheClassNames(): void
    {
        Config::set('mfa.storage.connection', 'other');

        self::assertSame('secondary', (new SecondaryConnectionFactor)->getConnectionName());

        Config::set('mfa.storage.connection', null);
    }

    /**
     * @return void
     */
    public function testUniqueIdsReturnsIdColumn(): void
    {
        self::assertSame(['id'], (new Factor)->uniqueIds());
    }

    /**
     * So a read never hands back the driver's native type.
     *
     * @return void
     */
    public function testPlainFillableAttributesCastToString(): void
    {
        $factor = new Factor;

        foreach (['authenticatable_type', 'authenticatable_id', 'type', 'label', 'destination', 'credential_reference', 'totp_algorithm', 'status', 'application'] as $attribute) {
            self::assertTrue($factor->hasCast($attribute, 'string'), $attribute);
        }
    }

    /**
     * @return void
     */
    public function testGeneratesUlidPrimaryKeyOnSave(): void
    {
        $user = TestUser::create(['email' => self::TEST_USER_EMAIL, 'mfa_enabled' => true]);

        $factor = new Factor([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => $this->authenticatableId($user),
            'type'                 => 'email',
        ]);
        $factor->save();

        self::assertIsString($factor->id);
        self::assertNotSame('', $factor->id);
        self::assertSame(26, strlen($factor->id));
    }

    /**
     * @return void
     */
    public function testAuthenticatableMorphToRelation(): void
    {
        $user = TestUser::create(['email' => self::TEST_USER_EMAIL, 'mfa_enabled' => true]);

        $factor = new Factor([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => $this->authenticatableId($user),
            'type'                 => 'totp',
        ]);
        $factor->save();

        $relation = $factor->authenticatable();

        self::assertInstanceOf(MorphTo::class, $relation);

        /** @var ?\Tests\Fixtures\Identities\TestUser $loaded */
        $loaded = $factor->authenticatable()->getResults();

        self::assertInstanceOf(TestUser::class, $loaded);
        self::assertSame($user->getKey(), $loaded->getKey());
    }

    /**
     * @return void
     */
    public function testSecretRoundTripsThroughEncryption(): void
    {
        $factor = $this->persistFactorWithSecret('JBSWY3DPEHPK3PXP');

        $reloaded = Factor::query()->findOrFail($factor->id);

        self::assertSame('JBSWY3DPEHPK3PXP', $reloaded->secret);
    }

    /**
     * @return void
     */
    public function testRawSecretColumnIsNotStoredAsPlaintext(): void
    {
        $factor = $this->persistFactorWithSecret('JBSWY3DPEHPK3PXP');

        $raw = $factor->getConnection()
            ->table($factor->getTable())
            ->where('id', $factor->id)
            ->first(['secret']);

        self::assertNotNull($raw);

        /** @var mixed $rawSecret */
        $rawSecret = $raw->secret;
        self::assertIsString($rawSecret);
        self::assertNotSame('JBSWY3DPEHPK3PXP', $rawSecret);
    }

    /**
     * @return void
     */
    public function testANewFactorIsPendingNotPreferredAndHasNotFailed(): void
    {
        self::assertSame(['status' => 'pending', 'preferred' => false, 'consecutive_failures' => 0], (new Factor)->getAttributes());
    }

    /**
     * @return void
     */
    public function testEveryColumnButTheKeyAndTimestampsIsFillable(): void
    {
        self::assertSame([
            'authenticatable_type',
            'authenticatable_id',
            'type',
            'label',
            'destination',
            'credential_reference',
            'secret',
            'totp_algorithm',
            'totp_digits',
            'totp_period',
            'last_accepted_step',
            'status',
            'preferred',
            'consecutive_failures',
            'disabled_at',
            'locked_until',
            'application',
            'confirmed_at',
            'last_used_at',
        ], (new Factor)->getFillable());
    }

    /**
     * The full destination and the credential reference are hidden too.
     *
     * @return void
     */
    public function testSecretIsHiddenFromSerialization(): void
    {
        $user = TestUser::create(['email' => self::TEST_USER_EMAIL, 'mfa_enabled' => true]);

        $factor = new Factor([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => $this->authenticatableId($user),
            'type'                 => 'email',
            'secret'               => 'super-secret',
            'destination'          => 'alice@example.com',
            'credential_reference' => 'credential-1',
        ]);
        $factor->save();

        $array = $factor->toArray();

        self::assertArrayNotHasKey('secret', $array);
        self::assertArrayNotHasKey('destination', $array);
        self::assertArrayNotHasKey('credential_reference', $array);
        self::assertArrayHasKey('type', $array);
    }

    /**
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @return string
     */
    private function authenticatableId(TestUser $user): string
    {
        /** @var int $key */
        $key = $user->getKey();

        return (string) $key;
    }

    /**
     * @param  string  $secret
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function persistFactorWithSecret(string $secret): Factor
    {
        $user = TestUser::create(['email' => self::TEST_USER_EMAIL, 'mfa_enabled' => true]);

        $factor = new Factor([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => $this->authenticatableId($user),
            'type'                 => 'totp',
            'secret'               => $secret,
        ]);
        $factor->save();

        return $factor;
    }
}
