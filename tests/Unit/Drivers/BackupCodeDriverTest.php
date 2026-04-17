<?php

declare(strict_types = 1);

namespace Tests\Unit\Drivers;

use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Drivers\BackupCodeDriver;
use SineMacula\Laravel\Mfa\Models\Factor as FactorModel;
use Tests\Fixtures\NonModelEloquentBackupCodeFactor;
use Tests\Fixtures\TestUser;
use Tests\TestCase;

/**
 * Unit tests for `BackupCodeDriver`.
 *
 * Exercises the single-use backup-code verification path including
 * the atomic consumption UPDATE, the generation helpers, and the
 * getter surface.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class BackupCodeDriverTest extends TestCase
{
    /**
     * `issueChallenge()` must be a no-op for the backup-code driver
     * — backup codes are pre-generated, never re-issued.
     *
     * @return void
     */
    public function testIssueChallengeIsNoOp(): void
    {
        $driver = new BackupCodeDriver;
        $factor = $this->makeStubFactor(secret: 'abc');

        // No state change, no return value, no exception.
        $driver->issueChallenge($factor);

        self::assertSame('abc', $factor->getSecret());
    }

    /**
     * A null stored secret must short-circuit verify to false rather
     * than fall through to the hash compare.
     *
     * @return void
     */
    public function testVerifyReturnsFalseWhenStoredSecretIsNull(): void
    {
        $driver = new BackupCodeDriver;
        $factor = $this->makeStubFactor(secret: null);

        self::assertFalse($driver->verify($factor, 'anything'));
    }

    /**
     * An empty stored secret must short-circuit verify to false.
     *
     * @return void
     */
    public function testVerifyReturnsFalseWhenStoredSecretIsEmptyString(): void
    {
        $driver = new BackupCodeDriver;
        $factor = $this->makeStubFactor(secret: '');

        self::assertFalse($driver->verify($factor, 'anything'));
    }

    /**
     * A code that hashes to a different value than the stored secret
     * must fail verification.
     *
     * @return void
     */
    public function testVerifyReturnsFalseForWrongCodeHash(): void
    {
        $driver = new BackupCodeDriver;
        $factor = $this->makeStubFactor(secret: $driver->hash('CORRECT'));

        self::assertFalse($driver->verify($factor, 'INCORRECT'));
    }

    /**
     * A non-Eloquent factor must succeed on a hash match without any
     * persistence side-effect — single-use enforcement is the
     * orchestration layer's concern in that path.
     *
     * @return void
     */
    public function testVerifyReturnsTrueForNonEloquentFactorWithoutPersistence(): void
    {
        $driver = new BackupCodeDriver;
        $plain  = 'ABCDEFGHJK';
        $factor = $this->makeStubFactor(secret: $driver->hash($plain));

        self::assertTrue($driver->verify($factor, $plain));

        // Non-Eloquent factors have no persistence side-effect, the
        // stored secret remains unchanged — single-use enforcement is
        // the orchestration layer's concern for non-Eloquent factors.
        self::assertSame($driver->hash($plain), $factor->getSecret());
    }

    /**
     * An Eloquent factor must be consumed atomically: the in-memory
     * attribute and the underlying row both have their secret nulled
     * and replay must fail.
     *
     * @return void
     */
    public function testVerifyConsumesEloquentFactorAtomically(): void
    {
        $driver = new BackupCodeDriver;
        $plain  = 'CONSUMEME1';
        $factor = $this->makeEloquentFactor($driver->hash($plain));

        self::assertTrue($driver->verify($factor, $plain));

        // In-memory factor attribute cleared for the manager's
        // subsequent persist().
        self::assertNull($factor->getSecret());

        // Underlying row was updated in place — a fresh fetch sees
        // the nulled secret.
        /** @var \SineMacula\Laravel\Mfa\Models\Factor $fresh */
        $fresh = FactorModel::query()->where($factor->getKeyName(), $factor->getKey())->sole();
        self::assertNull($fresh->getSecret());

        // Replay against the now-consumed code fails.
        self::assertFalse($driver->verify($fresh, $plain));
    }

    /**
     * If a concurrent consumer deletes the row between the in-memory
     * hash compare and the conditional UPDATE the verify must report
     * failure rather than succeed.
     *
     * @return void
     */
    public function testVerifyReturnsFalseWhenConcurrentConsumerDeletedTheRow(): void
    {
        $driver = new BackupCodeDriver;
        $plain  = 'RACEDELETE';
        $hash   = $driver->hash($plain);
        $factor = $this->makeEloquentFactor($hash);

        // Simulate a concurrent request having already consumed AND
        // purged the row between the outer verify() loading the in-
        // memory factor and the atomic lockForUpdate() query running.
        DB::table($factor->getTable())
            ->where($factor->getKeyName(), $factor->getKey())
            ->delete();

        self::assertFalse($driver->verify($factor, $plain));
    }

    /**
     * An `EloquentFactor` implementation that is not actually an
     * Eloquent Model should take the early-return branch and return
     * `true` on a hash match.
     *
     * @return void
     */
    public function testVerifyReturnsTrueForEloquentFactorThatIsNotAnEloquentModel(): void
    {
        $driver = new BackupCodeDriver;
        $plain  = 'NONMODEL01';
        $factor = $this->makeNonModelEloquentFactor(
            secret: $driver->hash($plain),
        );

        self::assertTrue($driver->verify($factor, $plain));
    }

    /**
     * If a concurrent consumer nulls the secret between the in-memory
     * compare and the atomic UPDATE, verify must report failure.
     *
     * @return void
     */
    public function testVerifyReturnsFalseWhenConcurrentConsumeWinsFirst(): void
    {
        $driver = new BackupCodeDriver;
        $plain  = 'RACECODEAB';
        $hash   = $driver->hash($plain);
        $factor = $this->makeEloquentFactor($hash);

        // Simulate a concurrent request having already consumed the
        // code: null the secret directly on the underlying row between
        // the in-memory hash compare and the atomic UPDATE. The
        // in-memory attribute still holds the hash so the hash_equals
        // check passes, but the conditional UPDATE affects zero rows.
        DB::table($factor->getTable())
            ->where($factor->getKeyName(), $factor->getKey())
            ->update([$factor->getSecretName() => null]);

        self::assertFalse($driver->verify($factor, $plain));
    }

    /**
     * The driver getters must return the values supplied to the
     * constructor verbatim.
     *
     * @return void
     */
    public function testGettersReturnConstructorValues(): void
    {
        $driver = new BackupCodeDriver(
            codeLength: 14,
            alphabet: '01',
            codeCount: 7,
        );

        self::assertSame(14, $driver->getCodeLength());
        self::assertSame('01', $driver->getAlphabet());
        self::assertSame(7, $driver->getCodeCount());
    }

    /**
     * The driver's `NAME` constant must match the registered driver
     * key consumers reference in their config.
     *
     * @return void
     */
    public function testNameConstantMatchesDriverIdentifier(): void
    {
        self::assertSame('backup_code', BackupCodeDriver::NAME);
    }

    /**
     * Persist and return an Eloquent factor seeded with the given
     * secret hash against the shipped model.
     *
     * @param  string  $secretHash
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function makeEloquentFactor(string $secretHash): FactorModel
    {
        $user = TestUser::query()->create([
            'email'       => 'backup@example.com',
            'mfa_enabled' => true,
        ]);

        $factor                       = new FactorModel;
        $factor->driver               = BackupCodeDriver::NAME;
        $factor->secret               = $secretHash;
        $factor->authenticatable_type = $user->getMorphClass();
        $factor->authenticatable_id   = (string) $user->id;
        $factor->save();

        return $factor->refresh();
    }

    /**
     * Build an `EloquentFactor` implementation that is NOT an
     * Eloquent Model — exercises the `consumeAtomic()` early-return
     * branch where the non-Model path skips the conditional UPDATE
     * and returns `true` unconditionally.
     *
     * @param  string  $secret
     * @return \SineMacula\Laravel\Mfa\Contracts\EloquentFactor
     */
    private function makeNonModelEloquentFactor(#[\SensitiveParameter] string $secret): EloquentFactor
    {
        return new NonModelEloquentBackupCodeFactor($secret);
    }

    /**
     * Build a non-Eloquent `Factor` stub with the supplied stored
     * secret.
     *
     * @param  ?string  $secret
     * @return \SineMacula\Laravel\Mfa\Contracts\Factor
     */
    private function makeStubFactor(#[\SensitiveParameter] ?string $secret): Factor
    {
        return new class ($secret) extends \Tests\Fixtures\AbstractFactorStub {
            /**
             * Capture the seeded secret value.
             *
             * @param  ?string  $secret
             * @return void
             */
            public function __construct(

                /** Stored backup-code secret hash. */
                #[\SensitiveParameter]
                private readonly ?string $secret,

            ) {}

            /**
             * @return string
             */
            public function getDriver(): string
            {
                return BackupCodeDriver::NAME;
            }

            /**
             * @return ?string
             */
            public function getSecret(): ?string
            {
                return $this->secret;
            }
        };
    }
}
