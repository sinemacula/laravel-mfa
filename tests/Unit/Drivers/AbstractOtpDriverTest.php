<?php

declare(strict_types = 1);

namespace Tests\Unit\Drivers;

use Carbon\Carbon;
use Carbon\CarbonInterface;
use Illuminate\Contracts\Auth\Authenticatable;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Drivers\AbstractOtpDriver;
use SineMacula\Laravel\Mfa\Exceptions\UnsupportedFactorException;
use SineMacula\Laravel\Mfa\Models\Factor as FactorModel;
use Tests\TestCase;

/**
 * Unit tests for `AbstractOtpDriver`.
 *
 * Exercised via a thin anonymous subclass that captures `dispatch()`
 * invocations, allowing the shared issuance / verification logic to be
 * asserted without touching a concrete transport.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class AbstractOtpDriverTest extends TestCase
{
    public function testIssueChallengeThrowsWhenFactorIsNotEloquent(): void
    {
        $driver = $this->makeDriver();
        $factor = $this->makeNonEloquentFactor();

        $this->expectException(UnsupportedFactorException::class);
        $this->expectExceptionMessage('OTP drivers require a persistable EloquentFactor');

        $driver->issueChallenge($factor);
    }

    public function testIssueChallengeDispatchesThenPersistsInOrder(): void
    {
        $order  = [];
        $driver = $this->makeDriver(orderTracker: $order);
        $factor = $this->createTrackingFactor($order);

        $driver->issueChallenge($factor);

        self::assertCount(1, $driver->dispatched);
        self::assertSame($factor, $driver->dispatched[0]['factor']);

        $code = $driver->dispatched[0]['code'];
        self::assertIsString($code);
        self::assertMatchesRegularExpression('/^\d{6}$/', $code);

        // Dispatch must have happened before the persist-bearing issueCode()
        // call, and both sides must be observed.
        self::assertSame(['dispatch', 'issueCode', 'persist'], $order);

        $factor->refresh();

        self::assertSame($code, $factor->getCode());
        self::assertNotNull($factor->getExpiresAt());
    }

    public function testIssueChallengeDoesNotPersistWhenDispatchThrows(): void
    {
        $driver = $this->makeDriver(throwOnDispatch: true);
        $factor = $this->createEloquentFactor();

        try {
            $driver->issueChallenge($factor);
            self::fail('Expected dispatch to throw.');
        } catch (\RuntimeException $e) {
            self::assertSame('transport failure', $e->getMessage());
        }

        $factor->refresh();

        // Nothing was persisted — the model was never saved after the
        // throwing dispatch.
        self::assertNull($factor->getCode());
        self::assertNull($factor->getExpiresAt());
    }

    public function testVerifyReturnsFalseWhenStoredCodeIsNull(): void
    {
        $driver = $this->makeDriver();
        $factor = $this->makeStubFactor(code: null, expires: Carbon::now()->addMinute());

        self::assertFalse($driver->verify($factor, '123456'));
    }

    public function testVerifyReturnsFalseWhenExpiresAtIsNull(): void
    {
        $driver = $this->makeDriver();
        $factor = $this->makeStubFactor(code: '123456', expires: null);

        self::assertFalse($driver->verify($factor, '123456'));
    }

    public function testVerifyReturnsFalseWhenCodeHasExpired(): void
    {
        $driver = $this->makeDriver();
        $factor = $this->makeStubFactor(
            code: '123456',
            expires: Carbon::now()->subMinute(),
        );

        self::assertFalse($driver->verify($factor, '123456'));
    }

    public function testVerifyReturnsTrueForMatchingCode(): void
    {
        $driver = $this->makeDriver();
        $factor = $this->makeStubFactor(
            code: '654321',
            expires: Carbon::now()->addMinutes(5),
        );

        self::assertTrue($driver->verify($factor, '654321'));
    }

    public function testVerifyReturnsFalseForMismatchingCode(): void
    {
        $driver = $this->makeDriver();
        $factor = $this->makeStubFactor(
            code: '654321',
            expires: Carbon::now()->addMinutes(5),
        );

        self::assertFalse($driver->verify($factor, '000000'));
    }

    public function testGenerateSecretReturnsNull(): void
    {
        $driver = $this->makeDriver();

        self::assertNull($driver->generateSecret());
    }

    public function testGettersReturnConstructorValues(): void
    {
        $driver = $this->makeDriver(codeLength: 8, expiry: 15, maxAttempts: 5);

        self::assertSame(8, $driver->getCodeLength());
        self::assertSame(15, $driver->getExpiry());
        self::assertSame(5, $driver->getMaxAttempts());
        self::assertNull($driver->getAlphabet());
    }

    public function testGeneratedCodeIsZeroPaddedNumericOfConfiguredLength(): void
    {
        $driver = $this->makeDriver(codeLength: 8);
        $factor = $this->createEloquentFactor();

        $driver->issueChallenge($factor);

        $code = $driver->dispatched[0]['code'];

        self::assertIsString($code);
        self::assertSame(8, strlen($code));
        self::assertMatchesRegularExpression('/^\d{8}$/', $code);
    }

    public function testConstructorRejectsEmptyAlphabet(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        // Asserting the distinguishing suffix (not just the shared
        // prefix) so a future refactor that swaps the two branch
        // strings cannot silently flip the diagnostic.
        $this->expectExceptionMessage('received an empty string.');

        $this->makeDriver(alphabet: '');
    }

    public function testConstructorRejectsSingleCharacterAlphabet(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('received a single character.');

        $this->makeDriver(alphabet: 'A');
    }

    public function testGetAlphabetReturnsConfiguredValue(): void
    {
        $driver = $this->makeDriver(alphabet: 'ABCDEF');

        self::assertSame('ABCDEF', $driver->getAlphabet());
    }

    public function testGeneratedCodeDrawsFromTwoCharacterAlphabet(): void
    {
        $driver = $this->makeDriver(codeLength: 20, alphabet: 'AB');
        $factor = $this->createEloquentFactor();

        $driver->issueChallenge($factor);

        $code = $driver->dispatched[0]['code'];

        self::assertIsString($code);
        self::assertSame(20, strlen($code));
        self::assertMatchesRegularExpression('/^[AB]{20}$/', $code);
    }

    public function testGeneratedCodeDrawsFromHexAlphabet(): void
    {
        $driver = $this->makeDriver(codeLength: 10, alphabet: '0123456789ABCDEF');
        $factor = $this->createEloquentFactor();

        $driver->issueChallenge($factor);

        $code = $driver->dispatched[0]['code'];

        self::assertIsString($code);
        self::assertMatchesRegularExpression('/^[0-9A-F]{10}$/', $code);
    }

    /**
     * Build a concrete subclass of the abstract driver that records
     * every `dispatch()` invocation, optionally throws, and captures
     * the order of the dispatch / issueCode / persist calls against
     * an externally supplied tracker array.
     *
     * @param  int  $codeLength
     * @param  int  $expiry
     * @param  int  $maxAttempts
     * @param  bool  $throwOnDispatch
     * @param  ?string  $alphabet
     * @param  list<string>  $orderTracker
     */
    private function makeDriver(
        int $codeLength = 6,
        int $expiry = 10,
        int $maxAttempts = 3,
        bool $throwOnDispatch = false,
        ?string $alphabet = null,
        array &$orderTracker = [],
    ): AbstractOtpDriver {
        $driver = new class ($codeLength, $expiry, $maxAttempts, $alphabet, $throwOnDispatch) extends AbstractOtpDriver {
            /** @var list<array{factor: EloquentFactor, code: string}> */
            public array $dispatched = [];

            /** @var array<int, string> */
            public array $order = [];

            public function __construct(
                int $codeLength,
                int $expiry,
                int $maxAttempts,
                ?string $alphabet,
                private readonly bool $throwOnDispatch,
            ) {
                parent::__construct($codeLength, $expiry, $maxAttempts, $alphabet);
            }

            public function bindOrderRef(array &$tracker): void
            {
                $this->order = &$tracker;
            }

            protected function dispatch(
                EloquentFactor $factor,
                #[\SensitiveParameter]
                string $code,
            ): void {
                $this->order[]      = 'dispatch';
                $this->dispatched[] = ['factor' => $factor, 'code' => $code];

                if ($this->throwOnDispatch) {
                    throw new \RuntimeException('transport failure');
                }
            }
        };

        $driver->bindOrderRef($orderTracker);

        return $driver;
    }

    /**
     * Persist a `FactorModel` subclass whose `issueCode()` and
     * `persist()` methods append to the shared order tracker so call
     * ordering can be asserted from the outside.
     *
     * @param  list<string>  $tracker
     */
    private function createTrackingFactor(array &$tracker): FactorModel
    {
        $user = \Tests\Fixtures\TestUser::query()->create([
            'email'       => 'otp@example.com',
            'mfa_enabled' => true,
        ]);

        $factor = new class extends FactorModel {
            /** @var array<int, string> */
            public array $tracker = [];

            public function bindTracker(array &$tracker): void
            {
                $this->tracker = &$tracker;
            }

            public function issueCode(
                #[\SensitiveParameter]
                string $code,
                \Carbon\CarbonInterface $expiresAt,
            ): void {
                $this->tracker[] = 'issueCode';
                parent::issueCode($code, $expiresAt);
            }

            public function persist(): void
            {
                $this->tracker[] = 'persist';
                parent::persist();
            }
        };

        $factor->bindTracker($tracker);
        $factor->driver               = 'email';
        $factor->recipient            = 'otp@example.com';
        $factor->authenticatable_type = $user->getMorphClass();
        $factor->authenticatable_id   = (string) $user->getKey();
        $factor->save();

        return $factor;
    }

    /**
     * Create a persisted Eloquent factor wired to a freshly inserted
     * test user so both dispatch and persistence can be observed.
     */
    private function createEloquentFactor(): FactorModel
    {
        $user = \Tests\Fixtures\TestUser::query()->create([
            'email'       => 'otp@example.com',
            'mfa_enabled' => true,
        ]);

        $factor                       = new FactorModel;
        $factor->driver               = 'email';
        $factor->recipient            = 'otp@example.com';
        $factor->authenticatable_type = $user->getMorphClass();
        $factor->authenticatable_id   = (string) $user->getKey();

        // Wrap save in a subclass-aware persist via the trait's hook.
        $factor->save();

        return $factor;
    }

    /**
     * Build a non-Eloquent `Factor` stub — enough surface for the
     * abstract driver to reject it through `UnsupportedFactorException`.
     */
    private function makeNonEloquentFactor(): Factor
    {
        return new class implements Factor {
            public function getFactorIdentifier(): mixed
            {
                return 'stub';
            }

            public function getDriver(): string
            {
                return 'email';
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
                return null;
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
     * Build a non-Eloquent `Factor` stub returning the supplied code
     * and expiry so the `verify()` branches can be exercised without
     * touching the database.
     *
     * @param  ?string  $code
     * @param  ?CarbonInterface  $expires
     */
    private function makeStubFactor(?string $code, ?CarbonInterface $expires): Factor
    {
        return new class ($code, $expires) implements Factor {
            public function __construct(
                private readonly ?string $code,
                private readonly ?CarbonInterface $expires,
            ) {}

            public function getFactorIdentifier(): mixed
            {
                return 'stub';
            }

            public function getDriver(): string
            {
                return 'email';
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
                return null;
            }

            public function getCode(): ?string
            {
                return $this->code;
            }

            public function getExpiresAt(): ?CarbonInterface
            {
                return $this->expires;
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
