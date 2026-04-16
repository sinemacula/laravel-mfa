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
use Tests\Fixtures\DispatchTrackingOtpDriver;
use Tests\Fixtures\Exceptions\DispatchTransportFailureException;
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
    /** @var string Stored-code fixture used as the "expected" side of the verify-mismatch tests. */
    private const string STORED_CODE = '123456';

    /** @var string Distinct second-form code so verify-match tests are not satisfied by accidental collision. */
    private const string MATCHING_CODE = '654321';

    /** @var string Address fixture reused across the persisted-factor scaffolding helpers. */
    private const string OTP_RECIPIENT = 'otp@example.com';

    /**
     * `issueChallenge()` must reject any factor that does not
     * implement `EloquentFactor` since OTP drivers persist state
     * between dispatch and verify.
     *
     * @return void
     */
    public function testIssueChallengeThrowsWhenFactorIsNotEloquent(): void
    {
        $driver = $this->makeDriver();
        $factor = $this->makeNonEloquentFactor();

        $this->expectException(UnsupportedFactorException::class);
        $this->expectExceptionMessage('OTP drivers require a persistable EloquentFactor');

        $driver->issueChallenge($factor);
    }

    /**
     * Issuance must dispatch the code to the transport before
     * persisting it on the factor — observed via a shared call-order
     * tracker.
     *
     * @return void
     */
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

    /**
     * If the dispatch step throws the issued code must NOT have been
     * persisted on the factor — issuance is all-or-nothing.
     *
     * @return void
     */
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

    /**
     * `verify()` must report false when the factor has no stored
     * code regardless of submitted input.
     *
     * @return void
     */
    public function testVerifyReturnsFalseWhenStoredCodeIsNull(): void
    {
        $driver = $this->makeDriver();
        $factor = $this->makeStubFactor(code: null, expires: Carbon::now()->addMinute());

        self::assertFalse($driver->verify($factor, self::STORED_CODE));
    }

    /**
     * `verify()` must report false when the factor has a stored code
     * but no expiry timestamp.
     *
     * @return void
     */
    public function testVerifyReturnsFalseWhenExpiresAtIsNull(): void
    {
        $driver = $this->makeDriver();
        $factor = $this->makeStubFactor(code: self::STORED_CODE, expires: null);

        self::assertFalse($driver->verify($factor, self::STORED_CODE));
    }

    /**
     * An expired stored code must always fail verification.
     *
     * @return void
     */
    public function testVerifyReturnsFalseWhenCodeHasExpired(): void
    {
        $driver = $this->makeDriver();
        $factor = $this->makeStubFactor(
            code: self::STORED_CODE,
            expires: Carbon::now()->subMinute(),
        );

        self::assertFalse($driver->verify($factor, self::STORED_CODE));
    }

    /**
     * A submitted code matching the stored code with a future expiry
     * must verify successfully.
     *
     * @return void
     */
    public function testVerifyReturnsTrueForMatchingCode(): void
    {
        $driver = $this->makeDriver();
        $factor = $this->makeStubFactor(
            code: self::MATCHING_CODE,
            expires: Carbon::now()->addMinutes(5),
        );

        self::assertTrue($driver->verify($factor, self::MATCHING_CODE));
    }

    /**
     * A submitted code that does not match the stored code must fail
     * verification.
     *
     * @return void
     */
    public function testVerifyReturnsFalseForMismatchingCode(): void
    {
        $driver = $this->makeDriver();
        $factor = $this->makeStubFactor(
            code: self::MATCHING_CODE,
            expires: Carbon::now()->addMinutes(5),
        );

        self::assertFalse($driver->verify($factor, '000000'));
    }

    /**
     * OTP drivers do not use a persistent secret — `generateSecret()`
     * must return null.
     *
     * @return void
     */
    public function testGenerateSecretReturnsNull(): void
    {
        $driver = $this->makeDriver();

        self::assertNull($driver->generateSecret());
    }

    /**
     * The driver getters must return the values supplied to the
     * constructor verbatim.
     *
     * @return void
     */
    public function testGettersReturnConstructorValues(): void
    {
        $driver = $this->makeDriver(codeLength: 8, expiry: 15, maxAttempts: 5);

        self::assertSame(8, $driver->getCodeLength());
        self::assertSame(15, $driver->getExpiry());
        self::assertSame(5, $driver->getMaxAttempts());
        self::assertNull($driver->getAlphabet());
    }

    /**
     * With no alphabet configured the generated code must be
     * zero-padded numeric of the configured length.
     *
     * @return void
     */
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

    /**
     * The constructor must reject an empty alphabet with a clear
     * `InvalidArgumentException` carrying the distinguishing
     * "received an empty string." suffix.
     *
     * @return void
     */
    public function testConstructorRejectsEmptyAlphabet(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        // Asserting the distinguishing suffix (not just the shared
        // prefix) so a future refactor that swaps the two branch
        // strings cannot silently flip the diagnostic.
        $this->expectExceptionMessage('received an empty string.');

        $this->makeDriver(alphabet: '');
    }

    /**
     * The constructor must reject a single-character alphabet with a
     * clear `InvalidArgumentException` carrying the distinguishing
     * "received a single character." suffix.
     *
     * @return void
     */
    public function testConstructorRejectsSingleCharacterAlphabet(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('received a single character.');

        $this->makeDriver(alphabet: 'A');
    }

    /**
     * `getAlphabet()` must return the configured alphabet verbatim.
     *
     * @return void
     */
    public function testGetAlphabetReturnsConfiguredValue(): void
    {
        $driver = $this->makeDriver(alphabet: 'ABCDEF');

        self::assertSame('ABCDEF', $driver->getAlphabet());
    }

    /**
     * A two-character alphabet must produce codes whose every
     * character is drawn from that alphabet.
     *
     * @return void
     */
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

    /**
     * A hex alphabet must produce codes whose every character is a
     * valid hex digit.
     *
     * @return void
     */
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
     * @param  array<int, string>  $orderTracker
     * @return \Tests\Fixtures\DispatchTrackingOtpDriver
     */
    private function makeDriver(
        int $codeLength = 6,
        int $expiry = 10,
        int $maxAttempts = 3,
        bool $throwOnDispatch = false,
        ?string $alphabet = null,
        array &$orderTracker = [],
    ): DispatchTrackingOtpDriver {
        $driver = new class ($codeLength, $expiry, $maxAttempts, $alphabet, $throwOnDispatch) extends DispatchTrackingOtpDriver {
            /**
             * Wire the configured driver state and the dispatch
             * behaviour switch.
             *
             * @param  int  $codeLength
             * @param  int  $expiry
             * @param  int  $maxAttempts
             * @param  ?string  $alphabet
             * @param  bool  $throwOnDispatch
             * @return void
             */
            public function __construct(
                int $codeLength,
                int $expiry,
                int $maxAttempts,
                ?string $alphabet,
                private readonly bool $throwOnDispatch,
            ) {
                parent::__construct($codeLength, $expiry, $maxAttempts, $alphabet);
            }

            /**
             * Capture every dispatch invocation; throw on demand to
             * simulate transport failure.
             *
             * @param  \SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
             * @param  string  $code
             * @return void
             *
             * @throws \Tests\Fixtures\Exceptions\DispatchTransportFailureException
             */
            protected function dispatch(
                EloquentFactor $factor,
                #[\SensitiveParameter]
                string $code,
            ): void {
                $this->order[]      = 'dispatch';
                $this->dispatched[] = ['factor' => $factor, 'code' => $code];

                if ($this->throwOnDispatch) {
                    throw new DispatchTransportFailureException('transport failure');
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
     * @param  array<int, string>  $tracker
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function createTrackingFactor(array &$tracker): FactorModel
    {
        $user = \Tests\Fixtures\TestUser::query()->create([
            'email'       => self::OTP_RECIPIENT,
            'mfa_enabled' => true,
        ]);

        $factor = new class extends FactorModel {
            /** @var array<int, string> */
            public array $tracker = [];

            /**
             * Bind the externally owned order tracker by reference so
             * persistence-side calls can be observed.
             *
             * @param  array<int, string>  $tracker
             * @return void
             */
            public function bindTracker(array &$tracker): void
            {
                $this->tracker = &$tracker;
            }

            /**
             * Record the call order before delegating to the parent
             * implementation.
             *
             * @param  string  $code
             * @param  \Carbon\CarbonInterface  $expiresAt
             * @return void
             */
            public function issueCode(
                #[\SensitiveParameter]
                string $code,
                \Carbon\CarbonInterface $expiresAt,
            ): void {
                $this->tracker[] = 'issueCode';
                parent::issueCode($code, $expiresAt);
            }

            /**
             * Record the call order before delegating to the parent
             * implementation.
             *
             * @return void
             */
            public function persist(): void
            {
                $this->tracker[] = 'persist';
                parent::persist();
            }
        };

        $factor->bindTracker($tracker);
        $factor->driver               = 'email';
        $factor->recipient            = self::OTP_RECIPIENT;
        $factor->authenticatable_type = $user->getMorphClass();
        $factor->authenticatable_id   = (string) $user->id;
        $factor->save();

        return $factor;
    }

    /**
     * Create a persisted Eloquent factor wired to a freshly inserted
     * test user so both dispatch and persistence can be observed.
     *
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function createEloquentFactor(): FactorModel
    {
        $user = \Tests\Fixtures\TestUser::query()->create([
            'email'       => self::OTP_RECIPIENT,
            'mfa_enabled' => true,
        ]);

        $factor                       = new FactorModel;
        $factor->driver               = 'email';
        $factor->recipient            = self::OTP_RECIPIENT;
        $factor->authenticatable_type = $user->getMorphClass();
        $factor->authenticatable_id   = (string) $user->id;

        // Wrap save in a subclass-aware persist via the trait's hook.
        $factor->save();

        return $factor;
    }

    /**
     * Build a non-Eloquent `Factor` stub — enough surface for the
     * abstract driver to reject it through `UnsupportedFactorException`.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\Factor
     */
    private function makeNonEloquentFactor(): Factor
    {
        return new class implements Factor {
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
                return 'email';
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
                return null;
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
     * @param  ?\Carbon\CarbonInterface  $expires
     * @return \SineMacula\Laravel\Mfa\Contracts\Factor
     */
    private function makeStubFactor(?string $code, ?CarbonInterface $expires): Factor
    {
        return new class ($code, $expires) implements Factor {
            /**
             * Capture the seeded code / expiry pair.
             *
             * @param  ?string  $code
             * @param  ?\Carbon\CarbonInterface  $expires
             * @return void
             */
            public function __construct(
                private readonly ?string $code,
                private readonly ?CarbonInterface $expires,
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
                return 'email';
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
                return null;
            }

            /**
             * @return ?string
             */
            public function getCode(): ?string
            {
                return $this->code;
            }

            /**
             * @return ?\Carbon\CarbonInterface
             */
            public function getExpiresAt(): ?CarbonInterface
            {
                return $this->expires;
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
                return false;
            }
        };
    }
}
