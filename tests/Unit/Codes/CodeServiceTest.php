<?php

declare(strict_types = 1);

namespace Tests\Unit\Codes;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Codes\CodeService;
use SineMacula\Laravel\Mfa\Codes\DeliveredCodes;
use SineMacula\Laravel\Mfa\Drivers\SmsDriver;
use SineMacula\Laravel\Mfa\Enums\CodeCheck;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Exceptions\CodeDeliveryFailedException;
use SineMacula\Laravel\Mfa\Exceptions\UnsupportedFactorException;
use SineMacula\Laravel\Mfa\Models\Code;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use Tests\Fixtures\Codes\LeakingSmsSender;
use Tests\Fixtures\Codes\RecordingCodeDriver;
use Tests\Fixtures\Factors\InMemoryFactor;
use Tests\Fixtures\Factors\TotpStubFactor;
use Tests\Fixtures\Factors\UncastOwnerKeyFactor;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Secrets\RecordedTrace;
use Tests\TestCase;

/**
 * Tests for `CodeService`: a code is stored and delivered in the identity's
 * factor state transaction and reported once committed; a refused send delivers
 * and reports nothing; a delivery that fails keeps nothing, and surfaces
 * scrubbed of the code and the destination; and only a stored factor owned by
 * the binding's identity has codes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CodeService::class)]
final class CodeServiceTest extends TestCase
{
    /** @var string The code the engine draws. */
    private const string CODE = '123456';

    /** @var string The address the factor delivers to. */
    private const string ADDRESS = 'ada@example.test';

    /** @var string The phone number an SMS factor delivers to. */
    private const string PHONE = '+447700900123';

    /**
     * A code sent is delivered to the factor's destination, reported with its
     * challenge and the factor's masked destination, and accepted once for its
     * binding.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACodeIsDeliveredReportedAndAcceptedOnce(): void
    {
        [$user, $factor] = $this->factor();

        $driver = new RecordingCodeDriver;
        $result = $this->service()->send($factor, self::binding($user), $driver);

        self::assertTrue($result->wasSent());
        self::assertNotNull($result->challengeId);
        self::assertSame(self::ADDRESS, $driver->delivered[0]['destination']);
        self::assertSame(self::CODE, $driver->lastCode());
        self::assertSame($result->expiresAt?->getTimestamp(), $driver->delivered[0]['expires_at']->getTimestamp());

        self::assertSame(CodeCheck::ACCEPTED, $this->service()->check($factor, self::binding($user), self::CODE, $result->challengeId));
        self::assertSame(CodeCheck::REPLAYED, $this->service()->check($factor, self::binding($user), self::CODE, $result->challengeId));
    }

    /**
     * A code sent inside a transaction that rolls back is not kept.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACodeRolledBackIsNotKept(): void
    {
        [$user, $factor] = $this->factor();

        DB::beginTransaction();

        $this->service()->send($factor, self::binding($user), new RecordingCodeDriver);

        DB::rollBack();

        self::assertSame(0, Code::query()->count());
    }

    /**
     * A send refused for its cooldown delivers nothing, and says how long to
     * wait.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefusedSendDeliversNothing(): void
    {
        [$user, $factor] = $this->factor();

        $driver = new RecordingCodeDriver;

        $this->service()->send($factor, self::binding($user), $driver);

        $result = $this->service()->send($factor, self::binding($user), $driver);

        self::assertFalse($result->wasSent());
        self::assertSame(FailureReason::SENDING_CAPPED, $result->reason);
        self::assertSame(60, $result->retryAfter);
        self::assertCount(1, $driver->delivered);
    }

    /**
     * A delivery that throws keeps no code and spends no cooldown: the next
     * send goes out at once. The failure surfaces as the package's own
     * exception, naming the factor with its destination masked, with the
     * driver's failure as the previous one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailedDeliveryKeepsNothing(): void
    {
        [$user, $factor] = $this->factor();

        $driver       = new RecordingCodeDriver;
        $driver->fail = true;

        try {
            $this->service()->send($factor, self::binding($user), $driver);
            self::fail('Expected the delivery to fail.');
        } catch (CodeDeliveryFailedException $exception) {
            self::assertSame('The code could not be delivered to the email factor at a**@example.test.', $exception->getMessage());
            self::assertSame('a**@example.test', $exception->factor->maskedDestination);
            self::assertSame('The transport failed.', $exception->getPrevious()?->getMessage());
        }

        self::assertSame(0, Code::query()->count());

        $driver->fail = false;

        self::assertTrue($this->service()->send($factor, self::binding($user), $driver)->wasSent());
    }

    /**
     * Rows of whether PHP records the arguments of each call in a trace, as a
     * development configuration does, or ignores them, as a production one
     * does.
     *
     * @return iterable<string, array{bool}>
     */
    public static function traceArguments(): iterable
    {
        yield 'arguments recorded' => [true];
        yield 'arguments ignored' => [false];
    }

    /**
     * A sender's failure that quotes the code and the phone number, in its
     * message, a previous exception's message and its trace, surfaces as an
     * exception naming neither, over the failure scrubbed of both, whether or
     * not PHP recorded the arguments; nothing is kept.
     *
     * @param  bool  $arguments
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('traceArguments')]
    public function testAFailedDeliveryIsScrubbedOfTheCodeAndTheDestination(bool $arguments): void
    {
        [$user, $factor] = $this->factor('sms', self::PHONE);

        $driver    = new SmsDriver(new LeakingSmsSender);
        $exception = RecordedTrace::thrownBy(fn () => $this->service()->send($factor, self::binding($user), $driver), $arguments);

        self::assertInstanceOf(CodeDeliveryFailedException::class, $exception);
        self::assertSame('The code could not be delivered to the sms factor at *********0123.', $exception->getMessage());

        $failure = $exception->getPrevious();

        self::assertInstanceOf(\RuntimeException::class, $failure);
        self::assertSame('The gateway refused the message to [redacted].', $failure->getMessage());
        self::assertStringStartsWith('Gateway said: invalid body "', (string) $failure->getPrevious()?->getMessage());
        self::assertStringEndsWith('[redacted]"', (string) $failure->getPrevious()?->getMessage());

        for ($current = $exception; $current !== null; $current = $current->getPrevious()) {
            foreach ([self::CODE, self::PHONE] as $plaintext) {
                self::assertStringNotContainsString($plaintext, $current->getMessage());
                self::assertStringNotContainsString($plaintext, $current->getTraceAsString());

                foreach (RecordedTrace::strings($current) as $string) {
                    self::assertStringNotContainsString($plaintext, $string);
                }
            }
        }

        self::assertSame(0, Code::query()->count());
    }

    /**
     * A send that waits for the locks is timed from when it holds them: its
     * code's lifetime and its cooldown run from then, not from when it began
     * waiting.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASendIsTimedOnceItHoldsTheLocks(): void
    {
        [$user, $factor] = $this->factor();

        $waited = false;

        Factor::retrieved(function () use (&$waited): void {

            if ($waited) {
                return;
            }

            $waited = true;

            $this->travelTo(CarbonImmutable::parse('2026-11-01 12:00:50'));
        });

        $result = $this->service()->send($factor, self::binding($user), new RecordingCodeDriver);

        self::assertSame(CarbonImmutable::parse('2026-11-01 12:10:50')->getTimestamp(), $result->expiresAt?->getTimestamp());

        $this->travelTo(CarbonImmutable::parse('2026-11-01 12:00:59'));

        self::assertSame(51, $this->service()->send($factor, self::binding($user), new RecordingCodeDriver)->retryAfter);
    }

    /**
     * A factor a concurrent change removed is not found under the lock, and
     * nothing is sent.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARemovedFactorIsNotFound(): void
    {
        [$user, $factor] = $this->factor();

        Factor::query()->whereKey($factor->getKey())->delete();

        $driver = new RecordingCodeDriver;
        $result = $this->service()->send($factor, self::binding($user), $driver);

        self::assertSame(FailureReason::NOT_FOUND, $result->reason);
        self::assertNull($result->retryAfter);
        self::assertSame([], $driver->delivered);
        self::assertSame(0, Code::query()->count());
    }

    /**
     * A factor that is not stored has no codes.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFactorThatIsNotStoredIsRefused(): void
    {
        $user = TestUser::query()->create(['email' => self::ADDRESS, 'mfa_enabled' => true]);

        $factors = [
            new InMemoryFactor(type: 'email', destination: self::ADDRESS, authenticatable: $user),
            new TotpStubFactor(null),
            new Factor(['type' => 'email']),
        ];

        foreach ($factors as $factor) {

            try {
                $this->service()->check($factor, self::binding($user), self::CODE, 'a-challenge');
                self::fail('Expected the factor to be refused.');
            } catch (UnsupportedFactorException $exception) {
                self::assertSame('Delivered codes need a stored EloquentFactor model; got ' . $factor::class . '.', $exception->getMessage());
            }
        }
    }

    /**
     * Rows of an owner key the factor may hold, and whether it names the
     * binding's identity: a string or an integer does, anything else does not,
     * even when it reads the same.
     *
     * @return iterable<string, array{\Closure(\Tests\Fixtures\Identities\TestUser): mixed, bool}>
     */
    public static function ownerKeys(): iterable
    {
        yield 'a string' => [static fn (TestUser $user): string => (string) $user->id, true];
        yield 'an integer' => [static fn (TestUser $user): int => $user->id, true];
        yield 'a float' => [static fn (TestUser $user): float => (float) $user->id, false];
    }

    /**
     * A factor's owner key names the binding's identity only when it is a
     * string or an integer that reads as the identity's key.
     *
     * @param  \Closure(\Tests\Fixtures\Identities\TestUser): mixed  $key
     * @param  bool  $owned
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('ownerKeys')]
    public function testOnlyAStringOrIntegerOwnerKeyNamesTheIdentity(\Closure $key, bool $owned): void
    {
        [$user, $stored] = $this->factor();

        $factor = (new UncastOwnerKeyFactor)->newFromBuilder($stored->getAttributes());

        $factor->setAttribute('authenticatable_id', $key($user));

        try {
            self::assertSame(CodeCheck::MISSING, $this->service()->check($factor, self::binding($user), self::CODE, 'a-challenge'));
            self::assertTrue($owned, 'Expected the owner key to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertFalse($owned, 'Expected the owner key to be accepted.');
            self::assertSame('A delivered code\'s binding must name the identity that owns the factor.', $exception->getMessage());
        }
    }

    /**
     * Rows of a key the stored factor may have, and whether a code can be bound
     * to it: a non-empty string or an integer can, anything else cannot.
     *
     * @return iterable<string, array{mixed, bool}>
     */
    public static function factorKeys(): iterable
    {
        yield 'an integer' => [42, true];
        yield 'an empty string' => ['', false];
        yield 'a float' => [4.2, false];
    }

    /**
     * Codes are bound only to a factor whose key is a non-empty string or an
     * integer.
     *
     * @param  mixed  $key
     * @param  bool  $bindable
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('factorKeys')]
    public function testOnlyAFactorWithAStringOrIntegerKeyHasCodes(mixed $key, bool $bindable): void
    {
        [$user, $factor] = $this->factor();

        $factor->setAttribute('id', $key);

        try {
            self::assertSame(CodeCheck::MISSING, $this->service()->check($factor, self::binding($user), self::CODE, 'a-challenge'));
            self::assertTrue($bindable, 'Expected the factor key to be refused.');
        } catch (UnsupportedFactorException $exception) {
            self::assertFalse($bindable, 'Expected the factor key to be accepted.');
            self::assertSame('A delivered code needs a factor with a string or integer key.', $exception->getMessage());
        }
    }

    /**
     * A binding naming another identity than the factor's owner is refused
     * before anything is sent or checked.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABindingForAnotherIdentityIsRefused(): void
    {
        [$user, $factor] = $this->factor();

        $other  = TestUser::query()->create(['email' => 'bob@example.test', 'mfa_enabled' => true]);
        $driver = new RecordingCodeDriver;

        $bindings = [
            new ProofBinding(TestUser::class, (string) $other->id, 'web', 'session-a', Purpose::SIGN_IN),
            new ProofBinding('App\Other', (string) $user->id, 'web', 'session-a', Purpose::SIGN_IN),
        ];

        foreach ($bindings as $binding) {

            try {
                $this->service()->send($factor, $binding, $driver);
                self::fail('Expected the binding to be refused.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('A delivered code\'s binding must name the identity that owns the factor.', $exception->getMessage());
            }
        }

        self::assertSame([], $driver->delivered);
    }

    /**
     * A user with a stored factor of the type (email, unless another is given),
     * the clock stopped, and the engine drawing a known code.
     *
     * @param  string  $type
     * @param  string  $destination
     * @return array{0: \Tests\Fixtures\Identities\TestUser, 1: \SineMacula\Laravel\Mfa\Models\Factor}
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function factor(string $type = 'email', string $destination = self::ADDRESS): array
    {
        $this->travelTo(CarbonImmutable::parse('2026-11-01 12:00:00'));

        $this->container()->instance(DeliveredCodes::class, new DeliveredCodes($this->container()->make(Repository::class), static fn (int $length): string => self::CODE));

        $user = TestUser::query()->create(['email' => self::ADDRESS, 'mfa_enabled' => true]);

        $factor = Factor::query()->create([
            'authenticatable_type' => $user->getMorphClass(),
            'authenticatable_id'   => (string) $user->id,
            'type'                 => $type,
            'destination'          => $destination,
            'status'               => 'confirmed',
        ]);

        return [$user, $factor];
    }

    /**
     * The code service.
     *
     * @return \SineMacula\Laravel\Mfa\Codes\CodeService
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function service(): CodeService
    {
        return $this->container()->make(CodeService::class);
    }

    /**
     * The sign-in binding of the user's codes.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @return \SineMacula\Laravel\Mfa\Proofs\ProofBinding
     */
    private static function binding(TestUser $user): ProofBinding
    {
        return new ProofBinding($user->getMorphClass(), (string) $user->id, 'web', 'session-a', Purpose::SIGN_IN);
    }
}
