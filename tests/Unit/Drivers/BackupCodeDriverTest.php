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
    public function testIssueChallengeIsNoOp(): void
    {
        $driver = new BackupCodeDriver;
        $factor = $this->makeStubFactor(secret: 'abc');

        // No state change, no return value, no exception.
        $driver->issueChallenge($factor);

        self::assertSame('abc', $factor->getSecret());
    }

    public function testVerifyReturnsFalseWhenStoredSecretIsNull(): void
    {
        $driver = new BackupCodeDriver;
        $factor = $this->makeStubFactor(secret: null);

        self::assertFalse($driver->verify($factor, 'anything'));
    }

    public function testVerifyReturnsFalseWhenStoredSecretIsEmptyString(): void
    {
        $driver = new BackupCodeDriver;
        $factor = $this->makeStubFactor(secret: '');

        self::assertFalse($driver->verify($factor, 'anything'));
    }

    public function testVerifyReturnsFalseForWrongCodeHash(): void
    {
        $driver = new BackupCodeDriver;
        $factor = $this->makeStubFactor(secret: $driver->hash('CORRECT'));

        self::assertFalse($driver->verify($factor, 'INCORRECT'));
    }

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
        /** @var FactorModel $fresh */
        $fresh = FactorModel::query()->where($factor->getKeyName(), $factor->getKey())->sole();
        self::assertNull($fresh->getSecret());

        // Replay against the now-consumed code fails.
        self::assertFalse($driver->verify($fresh, $plain));
    }

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

    public function testVerifyReturnsTrueForEloquentFactorThatIsNotAnEloquentModel(): void
    {
        $driver = new BackupCodeDriver;
        $plain  = 'NONMODEL01';
        $factor = $this->makeNonModelEloquentFactor(
            secret: $driver->hash($plain),
        );

        self::assertTrue($driver->verify($factor, $plain));
    }

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

    public function testGenerateSetReturnsDistinctCodes(): void
    {
        $driver = new BackupCodeDriver(codeCount: 25);
        $codes  = $driver->generateSet();

        self::assertCount(25, $codes);
        self::assertSame($codes, array_values(array_unique($codes)));
    }

    public function testHashIsDeterministicSha256(): void
    {
        $driver = new BackupCodeDriver;

        $first  = $driver->hash('STABLE-CODE');
        $second = $driver->hash('STABLE-CODE');

        self::assertSame($first, $second);
        self::assertSame(hash('sha256', 'STABLE-CODE'), $first);
    }

    public function testGenerateSecretReturnsSinglePlaintextCode(): void
    {
        $driver = new BackupCodeDriver(codeLength: 12, alphabet: 'XYZ');
        $secret = $driver->generateSecret();

        self::assertIsString($secret);
        self::assertSame(12, strlen($secret));
        self::assertMatchesRegularExpression('/^[XYZ]{12}$/', $secret);
    }

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

    public function testNameConstantMatchesDriverIdentifier(): void
    {
        self::assertSame('backup_code', BackupCodeDriver::NAME);
    }

    /**
     * Persist and return an Eloquent factor seeded with the given
     * secret hash against the shipped model.
     *
     * @param  string  $secretHash
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
        $factor->authenticatable_id   = (string) $user->getKey();
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
     */
    private function makeNonModelEloquentFactor(string $secret): EloquentFactor
    {
        return new class ($secret) implements EloquentFactor {
            public function __construct(
                private ?string $secret,
            ) {}

            public function authenticatable(): MorphTo
            {
                throw new \LogicException('not implemented');
            }

            public function getDriverName(): string
            {
                return 'driver';
            }

            public function getLabelName(): string
            {
                return 'label';
            }

            public function getRecipientName(): string
            {
                return 'recipient';
            }

            public function getSecretName(): string
            {
                return 'secret';
            }

            public function getCodeName(): string
            {
                return 'code';
            }

            public function getExpiresAtName(): string
            {
                return 'expires_at';
            }

            public function getAttemptsName(): string
            {
                return 'attempts';
            }

            public function getLockedUntilName(): string
            {
                return 'locked_until';
            }

            public function getLastAttemptedAtName(): string
            {
                return 'last_attempted_at';
            }

            public function getVerifiedAtName(): string
            {
                return 'verified_at';
            }

            public function recordAttempt(?CarbonInterface $at = null): void {}

            public function resetAttempts(): void {}

            public function applyLockout(CarbonInterface $until): void {}

            public function recordVerification(?CarbonInterface $at = null): void {}

            public function issueCode(
                #[\SensitiveParameter]
                string $code,
                CarbonInterface $expiresAt,
            ): void {}

            public function consumeCode(): void {}

            public function persist(): void {}

            public function getFactorIdentifier(): mixed
            {
                return 'non-model';
            }

            public function getDriver(): string
            {
                return BackupCodeDriver::NAME;
            }

            public function getLabel(): ?string
            {
                return null;
            }

            public function getRecipient(): ?string
            {
                return null;
            }

            public function getAuthenticatable(): ?Authenticatable
            {
                return null;
            }

            public function getSecret(): ?string
            {
                return $this->secret;
            }

            public function getCode(): ?string
            {
                return null;
            }

            public function getExpiresAt(): ?CarbonInterface
            {
                return null;
            }

            public function getAttempts(): int
            {
                return 0;
            }

            public function getLockedUntil(): ?CarbonInterface
            {
                return null;
            }

            public function isLocked(): bool
            {
                return false;
            }

            public function getLastAttemptedAt(): ?CarbonInterface
            {
                return null;
            }

            public function getVerifiedAt(): ?CarbonInterface
            {
                return null;
            }

            public function isVerified(): bool
            {
                return false;
            }
        };
    }

    /**
     * Build a non-Eloquent `Factor` stub with the supplied stored
     * secret.
     *
     * @param  ?string  $secret
     */
    private function makeStubFactor(?string $secret): Factor
    {
        return new class ($secret) implements Factor {
            public function __construct(
                private readonly ?string $secret,
            ) {}

            public function getFactorIdentifier(): mixed
            {
                return 'stub';
            }

            public function getDriver(): string
            {
                return BackupCodeDriver::NAME;
            }

            public function getLabel(): ?string
            {
                return null;
            }

            public function getRecipient(): ?string
            {
                return null;
            }

            public function getAuthenticatable(): ?Authenticatable
            {
                return null;
            }

            public function getSecret(): ?string
            {
                return $this->secret;
            }

            public function getCode(): ?string
            {
                return null;
            }

            public function getExpiresAt(): ?CarbonInterface
            {
                return null;
            }

            public function getAttempts(): int
            {
                return 0;
            }

            public function getLockedUntil(): ?CarbonInterface
            {
                return null;
            }

            public function isLocked(): bool
            {
                return false;
            }

            public function getLastAttemptedAt(): ?CarbonInterface
            {
                return null;
            }

            public function getVerifiedAt(): ?CarbonInterface
            {
                return null;
            }

            public function isVerified(): bool
            {
                return false;
            }
        };
    }
}
