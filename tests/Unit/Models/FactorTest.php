<?php

declare(strict_types = 1);

namespace Tests\Unit\Models;

use Illuminate\Database\Eloquent\Relations\MorphTo;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Facade;
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

    /** @var string */
    private const string TEST_USER_EMAIL = 'alice@example.com';

    /** @var string Cleartext OTP fixture used to assert the code-encryption round-trip. */
    private const string CLEARTEXT_CODE = '123456';

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
     * Test unique ids returns id column.
     *
     * @return void
     */
    public function testUniqueIdsReturnsIdColumn(): void
    {
        self::assertSame(['id'], (new Factor)->uniqueIds());
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
            'driver'               => 'email',
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
     * Test code round-trips through encryption when read back.
     *
     * @return void
     */
    public function testCodeRoundTripsThroughEncryption(): void
    {
        $factor = $this->persistFactorWithCode(self::CLEARTEXT_CODE);

        $reloaded = Factor::query()->findOrFail($factor->id);

        self::assertSame(self::CLEARTEXT_CODE, $reloaded->code);
    }

    /**
     * Test raw code column is not stored as plaintext.
     *
     * @return void
     */
    public function testRawCodeColumnIsNotStoredAsPlaintext(): void
    {
        $factor = $this->persistFactorWithCode(self::CLEARTEXT_CODE);

        $raw = $factor->getConnection()
            ->table($factor->getTable())
            ->where('id', $factor->id)
            ->first(['code']);

        self::assertNotNull($raw);

        /** @var mixed $rawCode */
        $rawCode = $raw->code;
        self::assertIsString($rawCode);
        self::assertNotSame(self::CLEARTEXT_CODE, $rawCode);
    }

    /**
     * Test secret and code are hidden from serialisation.
     *
     * @return void
     */
    public function testSecretAndCodeAreHiddenFromSerialisation(): void
    {
        $user = TestUser::create(['email' => self::TEST_USER_EMAIL, 'mfa_enabled' => true]);

        $factor = new Factor([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => $this->authenticatableId($user),
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

    /**
     * Return the test user's key as a string for morph-to wiring.
     *
     * @param  \Tests\Fixtures\TestUser  $user
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
            'driver'               => 'totp',
            'secret'               => $secret,
        ]);
        $factor->save();

        return $factor;
    }

    /**
     * Persist an email factor carrying the given plaintext OTP code.
     *
     * @param  string  $code
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function persistFactorWithCode(string $code): Factor
    {
        $user = TestUser::create(['email' => self::TEST_USER_EMAIL, 'mfa_enabled' => true]);

        $factor = new Factor([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => $this->authenticatableId($user),
            'driver'               => 'email',
            'recipient'            => 'verify@example.test',
            'code'                 => $code,
        ]);
        $factor->save();

        return $factor;
    }
}
