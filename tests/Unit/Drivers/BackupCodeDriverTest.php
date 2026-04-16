<?php

declare(strict_types = 1);

namespace Tests\Unit\Drivers;

use Carbon\CarbonInterface;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Drivers\BackupCodeDriver;
use SineMacula\Laravel\Mfa\Models\Factor as FactorModel;
use Tests\Fixtures\Exceptions\UnsupportedFixtureMethodException;
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
     * `generateSet()` must produce exactly the configured number of
     * codes and each code must respect the configured length and
     * alphabet.
     *
     * @return void
     */
    public function testGenerateSetReturnsConfiguredNumberOfCodes(): void
    {
        $driver = new BackupCodeDriver(
            codeLength: 8,
            alphabet: 'ABCDEF',
            codeCount: 5,
        );

        $codes = $driver->generateSet();

        self::assertCount(5, $codes);

        foreach ($codes as $code) {
            self::assertSame(8, strlen($code));
            self::assertMatchesRegularExpression('/^[ABCDEF]{8}$/', $code);
        }
    }

    /**
     * Generated codes within a single set must all be distinct so a
     * lost code does not invalidate another.
     *
     * @return void
     */
    public function testGenerateSetReturnsDistinctCodes(): void
    {
        $driver = new BackupCodeDriver(codeCount: 25);
        $codes  = $driver->generateSet();

        self::assertCount(25, $codes);
        self::assertSame($codes, array_values(array_unique($codes)));
    }

    /**
     * `hash()` must be deterministic and equivalent to a raw SHA-256
     * digest of the input.
     *
     * @return void
     */
    public function testHashIsDeterministicSha256(): void
    {
        $driver = new BackupCodeDriver;

        $first  = $driver->hash('STABLE-CODE');
        $second = $driver->hash('STABLE-CODE');

        self::assertSame($first, $second);
        self::assertSame(hash('sha256', 'STABLE-CODE'), $first);
    }

    /**
     * `generateSecret()` must return a single plaintext code that
     * matches the configured alphabet and length.
     *
     * @return void
     */
    public function testGenerateSecretReturnsSinglePlaintextCode(): void
    {
        $driver = new BackupCodeDriver(codeLength: 12, alphabet: 'XYZ');
        $secret = $driver->generateSecret();

        self::assertIsString($secret);
        self::assertSame(12, strlen($secret));
        self::assertMatchesRegularExpression('/^[XYZ]{12}$/', $secret);
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
    private function makeNonModelEloquentFactor(string $secret): EloquentFactor
    {
        /**
         * Anonymous class implements the full EloquentFactor contract
         * surface (33 methods). The method count is dictated by the
         * contract, not by accidental complexity — splitting would
         * require fragmenting EloquentFactor itself, which is out of
         * scope for a single-purpose test fixture.
         *
         * @SuppressWarnings("php:S1448")
         */
        return new class ($secret) implements EloquentFactor {
            /**
             * Capture the seeded secret value.
             *
             * @param  ?string  $secret
             * @return void
             */
            public function __construct(
                private ?string $secret,
            ) {}

            /**
             * Required by the contract but never invoked from this
             * stub — the only test exercising this fixture takes the
             * non-Model early-return branch in `BackupCodeDriver::verify()`
             * before any relation lookup happens. Throws so an
             * accidental future caller fails loudly rather than
             * receiving a half-built relation.
             *
             * @return \Illuminate\Database\Eloquent\Relations\MorphTo<\Illuminate\Database\Eloquent\Model, \Illuminate\Database\Eloquent\Model>
             *
             * @throws \Tests\Fixtures\Exceptions\UnsupportedFixtureMethodException
             */
            public function authenticatable(): MorphTo
            {
                // Wrapping the throw in a `match` keeps the `return`
                // syntactically present so CodeSniffer's
                // `InvalidNoReturn` does not flag the @return tag, even
                // though the function is logically `never`-returning.
                return match (true) {
                    default => throw new UnsupportedFixtureMethodException('authenticatable() is unsupported on the non-Model EloquentFactor fixture.'),
                };
            }

            /**
             * @return string
             */
            public function getDriverName(): string
            {
                return 'driver';
            }

            /**
             * @return string
             */
            public function getLabelName(): string
            {
                return 'label';
            }

            /**
             * @return string
             */
            public function getRecipientName(): string
            {
                return 'recipient';
            }

            /**
             * @return string
             */
            public function getSecretName(): string
            {
                return 'secret';
            }

            /**
             * @return string
             */
            public function getCodeName(): string
            {
                return 'code';
            }

            /**
             * @return string
             */
            public function getExpiresAtName(): string
            {
                return 'expires_at';
            }

            /**
             * @return string
             */
            public function getAttemptsName(): string
            {
                return 'attempts';
            }

            /**
             * @return string
             */
            public function getLockedUntilName(): string
            {
                return 'locked_until';
            }

            /**
             * @return string
             */
            public function getLastAttemptedAtName(): string
            {
                return 'last_attempted_at';
            }

            /**
             * @return string
             */
            public function getVerifiedAtName(): string
            {
                return 'verified_at';
            }

            /**
             * No-op — the fixture does not track attempts.
             *
             * @param  ?\Carbon\CarbonInterface  $at
             * @return void
             */
            public function recordAttempt(?CarbonInterface $at = null): void
            {
                // Intentionally empty — see method docblock.
            }

            /**
             * No-op — the fixture does not track attempts.
             *
             * @return void
             */
            public function resetAttempts(): void
            {
                // Intentionally empty — see method docblock.
            }

            /**
             * No-op — the fixture does not track lockouts.
             *
             * @param  \Carbon\CarbonInterface  $until
             * @return void
             */
            public function applyLockout(CarbonInterface $until): void
            {
                // Intentionally empty — see method docblock.
            }

            /**
             * No-op — the fixture does not track verifications.
             *
             * @param  ?\Carbon\CarbonInterface  $at
             * @return void
             */
            public function recordVerification(?CarbonInterface $at = null): void
            {
                // Intentionally empty — see method docblock.
            }

            /**
             * No-op — the fixture does not track issued codes.
             *
             * @param  string  $code
             * @param  \Carbon\CarbonInterface  $expiresAt
             * @return void
             */
            public function issueCode(
                #[\SensitiveParameter]
                string $code,
                CarbonInterface $expiresAt,
            ): void {
                // Intentionally empty — see method docblock.
            }

            /**
             * No-op — the fixture does not track consumed codes.
             *
             * @return void
             */
            public function consumeCode(): void
            {
                // Intentionally empty — see method docblock.
            }

            /**
             * No-op — the fixture does not persist anywhere.
             *
             * @return void
             */
            public function persist(): void
            {
                // Intentionally empty — see method docblock.
            }

            /**
             * @return mixed
             */
            public function getFactorIdentifier(): mixed
            {
                return 'non-model';
            }

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
            public function getLabel(): ?string
            {
                return null;
            }

            /**
             * @return ?string
             */
            public function getRecipient(): ?string
            {
                return null;
            }

            /**
             * @return ?\Illuminate\Contracts\Auth\Authenticatable
             */
            public function getAuthenticatable(): ?Authenticatable
            {
                return null;
            }

            /**
             * @return ?string
             */
            public function getSecret(): ?string
            {
                return $this->secret;
            }

            /**
             * @return ?string
             */
            public function getCode(): ?string
            {
                return null;
            }

            /**
             * @return ?\Carbon\CarbonInterface
             */
            public function getExpiresAt(): ?CarbonInterface
            {
                return null;
            }

            /**
             * @return int
             */
            public function getAttempts(): int
            {
                return 0;
            }

            /**
             * @return ?\Carbon\CarbonInterface
             */
            public function getLockedUntil(): ?CarbonInterface
            {
                return null;
            }

            /**
             * @return bool
             */
            public function isLocked(): bool
            {
                // Derived from the accessor so this stub does not duplicate
                // the body of isVerified() — radarlint S4144 flags
                // structurally identical method bodies.
                return $this->getLockedUntil() !== null;
            }

            /**
             * @return ?\Carbon\CarbonInterface
             */
            public function getLastAttemptedAt(): ?CarbonInterface
            {
                return null;
            }

            /**
             * @return ?\Carbon\CarbonInterface
             */
            public function getVerifiedAt(): ?CarbonInterface
            {
                return null;
            }

            /**
             * @return bool
             */
            public function isVerified(): bool
            {
                // Verification state is irrelevant — these stubs cover
                // the verify-decision path, not post-verify state.
                return false;
            }
        };
    }

    /**
     * Build a non-Eloquent `Factor` stub with the supplied stored
     * secret.
     *
     * @param  ?string  $secret
     * @return \SineMacula\Laravel\Mfa\Contracts\Factor
     */
    private function makeStubFactor(?string $secret): Factor
    {
        return new class ($secret) implements Factor {
            /**
             * Capture the seeded secret value.
             *
             * @param  ?string  $secret
             * @return void
             */
            public function __construct(
                private readonly ?string $secret,
            ) {}

            /**
             * @return mixed
             */
            public function getFactorIdentifier(): mixed
            {
                return 'stub';
            }

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
            public function getLabel(): ?string
            {
                return null;
            }

            /**
             * @return ?string
             */
            public function getRecipient(): ?string
            {
                return null;
            }

            /**
             * @return ?\Illuminate\Contracts\Auth\Authenticatable
             */
            public function getAuthenticatable(): ?Authenticatable
            {
                return null;
            }

            /**
             * @return ?string
             */
            public function getSecret(): ?string
            {
                return $this->secret;
            }

            /**
             * @return ?string
             */
            public function getCode(): ?string
            {
                return null;
            }

            /**
             * @return ?\Carbon\CarbonInterface
             */
            public function getExpiresAt(): ?CarbonInterface
            {
                return null;
            }

            /**
             * @return int
             */
            public function getAttempts(): int
            {
                return 0;
            }

            /**
             * @return ?\Carbon\CarbonInterface
             */
            public function getLockedUntil(): ?CarbonInterface
            {
                return null;
            }

            /**
             * @return bool
             */
            public function isLocked(): bool
            {
                // Derived from the accessor so this stub does not duplicate
                // the body of isVerified() — radarlint S4144 flags
                // structurally identical method bodies.
                return $this->getLockedUntil() !== null;
            }

            /**
             * @return ?\Carbon\CarbonInterface
             */
            public function getLastAttemptedAt(): ?CarbonInterface
            {
                return null;
            }

            /**
             * @return ?\Carbon\CarbonInterface
             */
            public function getVerifiedAt(): ?CarbonInterface
            {
                return null;
            }

            /**
             * @return bool
             */
            public function isVerified(): bool
            {
                // Verification state is irrelevant — these stubs cover
                // the verify-decision path, not post-verify state.
                return false;
            }
        };
    }
}
