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
 * Integration-leaning unit tests for the shipped `Factor` Eloquent model.
 *
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
     * Test implements eloquent factor contract.
     *
     * @return void
     */
    public function testImplementsEloquentFactorContract(): void
    {
        self::assertInstanceOf(EloquentFactor::class, new Factor);
    }

    /**
     * Test default table name is mfa factors.
     *
     * @return void
     */
    public function testDefaultTableNameIsMfaFactors(): void
    {
        $factor = new Factor;

        self::assertSame('mfa_factors', $factor->getTable());
    }

    /**
     * Test table name falls back to default when config facade is not
     * bootstrapped.
     *
     * @return void
     */
    public function testTableNameFallsBackToDefaultWhenConfigFacadeIsNotBootstrapped(): void
    {
        // Swap out the bound Facade application so `Config::string(...)`
        // throws, exercising the defensive fallback in
        // `resolveConfiguredTable`.
        $previous = Facade::getFacadeApplication();

        // Tear-down accepts null even though the upstream stub claims non-null
        // is required.
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
     * Test table name resolves from config.
     *
     * @return void
     */
    public function testTableNameResolvesFromConfig(): void
    {
        Config::set('mfa.factor.table', 'custom_factors');

        $factor = new Factor;

        self::assertSame('custom_factors', $factor->getTable());
    }

    /**
     * Test table name falls back to default when config is empty.
     *
     * @return void
     */
    public function testTableNameFallsBackToDefaultWhenConfigIsEmpty(): void
    {
        Config::set('mfa.factor.table', '');

        $factor = new Factor;

        self::assertSame('mfa_factors', $factor->getTable());
    }

    /**
     * The model lives on the storage connection, named even when it is the
     * default one: the default one when none is configured, the configured one
     * otherwise.
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
     * A subclass that names a connection of its own keeps it, so a model off
     * the storage connection is refused rather than silently moved.
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
     * Test unique ids returns id column.
     *
     * @return void
     */
    public function testUniqueIdsReturnsIdColumn(): void
    {
        self::assertSame(['id'], (new Factor)->uniqueIds());
    }

    /**
     * Every mass-assignable attribute without a richer cast is cast to a
     * string, so a read never hands back the driver's native type.
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
     * Test generates ulid primary key on save.
     *
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
     * Test authenticatable morph to relation.
     *
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
     * Test secret round-trips through encryption when read back.
     *
     * @return void
     */
    public function testSecretRoundTripsThroughEncryption(): void
    {
        $factor = $this->persistFactorWithSecret('JBSWY3DPEHPK3PXP');

        $reloaded = Factor::query()->findOrFail($factor->id);

        self::assertSame('JBSWY3DPEHPK3PXP', $reloaded->secret);
    }

    /**
     * Test raw secret column is not stored as plaintext.
     *
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
     * A new factor is pending, not preferred, and has not failed, before it is
     * stored.
     *
     * @return void
     */
    public function testANewFactorIsPendingNotPreferredAndHasNotFailed(): void
    {
        self::assertSame(['status' => 'pending', 'preferred' => false, 'consecutive_failures' => 0], (new Factor)->getAttributes());
    }

    /**
     * Every column is mass assignable but the key and the timestamps.
     *
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
     * Test the secret is hidden from serialisation, as are the full destination
     * and the credential reference.
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
     * Return the test user's key as a string for morph-to wiring.
     *
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
     * Persist a TOTP factor carrying the given plaintext secret.
     *
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
