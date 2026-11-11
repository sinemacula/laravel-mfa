<?php

declare(strict_types = 1);

namespace Tests\Unit\Secrets;

use Illuminate\Support\Collection;
use Monolog\Level;
use Monolog\LogRecord;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Codes\MfaCodeMessage;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Secrets\RedactSecrets;
use SineMacula\Laravel\Mfa\Secrets\RevealedSecret;
use Tests\Fixtures\Secrets\ForgedTrace;
use Tests\Fixtures\Secrets\RecordedTrace;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RedactSecrets::class)]
final class RedactSecretsTest extends TestCase
{
    /** @var string A TOTP secret. */
    private const string SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';

    /**
     * @return void
     */
    public function testRedactsTheRecord(): void
    {
        $record = (new RedactSecrets)($this->record(
            'Scan otpauth://totp/Acme?secret=' . self::SECRET,
            ['secret' => self::SECRET, 'shown' => new RevealedSecret(self::SECRET), 'label' => 'Phone'],
            ['code' => '482915', 'request_id' => 'abc'],
        ));

        self::assertSame('Scan [redacted]', $record->message);
        self::assertSame(['secret' => '[redacted]', 'shown' => '[redacted]', 'label' => 'Phone'], $record->context);
        self::assertSame(['code' => '[redacted]', 'request_id' => 'abc'], $record->extra);
    }

    /**
     * The trace's values are collected before the exception in the context is
     * scrubbed.
     *
     * @return void
     */
    public function testRedactsAMessageCopiedFromAnException(): void
    {
        $exception = ForgedTrace::onto(new \RuntimeException('Hashing 482915 failed.'), [
            ['file' => '/app/Http/Controllers/VerifyController.php', 'line' => 12, 'class' => MfaManager::class, 'type' => '->', 'function' => 'verify', 'args' => ['482915']],
        ]);

        $record = (new RedactSecrets)($this->record($exception->getMessage(), ['exception' => $exception], []));

        self::assertSame('Hashing [redacted] failed.', $record->message);
        self::assertSame('Hashing [redacted] failed.', $exception->getMessage());
    }

    /**
     * Values under a sensitive key, marked sensitive, or in a code message,
     * whose code goes whatever its length.
     *
     * @return void
     */
    public function testRedactsTheValuesTheRecordHoldsFromItsMessage(): void
    {
        $record = (new RedactSecrets)($this->record(
            'Sent 4821 to ada@example.test, then 739104 to +447700900123 for ' . self::SECRET,
            ['message' => (new MfaCodeMessage('4821', 10))->to('ada@example.test'), 'shown' => new RevealedSecret(self::SECRET)],
            ['sms' => ['phone_number' => '+447700900123', 'code' => '739104']],
        ));

        self::assertSame('Sent [redacted] to [redacted], then [redacted] to [redacted] for [redacted]', $record->message);
        self::assertSame(['message' => '[redacted]', 'shown' => '[redacted]'], $record->context);
        self::assertSame(['sms' => ['phone_number' => '[redacted]', 'code' => '[redacted]']], $record->extra);
    }

    /**
     * Recorded without arguments, it and every previous one lose the values the
     * record holds.
     *
     * @return void
     */
    public function testScrubsALoggedExceptionOfTheValuesTheRecordHolds(): void
    {
        $exception = RecordedTrace::thrownBy(static function (): never {
            throw new \RuntimeException('Rejected 482915', 0, new \LogicException('Previously rejected 482915'));
        }, false);

        self::assertArrayNotHasKey('args', $exception->getTrace()[0] ?? []);

        $record = (new RedactSecrets)($this->record('Delivery failed.', ['code' => '482915', 'exception' => $exception], []));

        self::assertSame(['code' => '[redacted]', 'exception' => $exception], $record->context);
        self::assertSame('Rejected [redacted]', $exception->getMessage());
        self::assertSame('Previously rejected [redacted]', $exception->getPrevious()?->getMessage());
    }

    /**
     * @return iterable<string, array{object, string}>
     */
    public static function objectPayloads(): iterable
    {
        yield 'a plain object' => [(object) ['code' => '482915'], \stdClass::class];
        yield 'a collection' => [new Collection(['code' => '482915']), Collection::class];

        $json = new class implements \JsonSerializable {
            /**
             * @return array<string, string>
             */
            #[\Override]
            public function jsonSerialize(): array
            {
                return ['code' => '482915'];
            }
        };

        yield 'a JsonSerializable' => [$json, get_debug_type($json)];
    }

    /**
     * @param  object  $payload
     * @param  string  $class
     * @return void
     */
    #[DataProvider('objectPayloads')]
    public function testRedactsTheValuesAnObjectHoldsFromTheMessage(object $payload, string $class): void
    {
        $record = (new RedactSecrets)($this->record('Rejected 482915', ['payload' => $payload], []));

        self::assertSame('Rejected [redacted]', $record->message);
        self::assertSame(['payload' => [$class => ['code' => '[redacted]']]], $record->context);
    }

    /**
     * Redacted whole without calling its methods, so one whose logged form
     * throws does not fail the log.
     *
     * @return void
     */
    public function testRedactsAnObjectUnderASecretKeyWithoutCallingIt(): void
    {
        $throwing = new class implements \JsonSerializable, \Stringable {
            /**
             * @return never
             *
             * @throws \LogicException
             */
            #[\Override]
            public function jsonSerialize(): never
            {
                throw new \LogicException('Not serialisable.');
            }

            /**
             * @return string
             *
             * @throws \LogicException
             */
            #[\Override]
            public function __toString(): string
            {
                throw new \LogicException('Not stringable.');
            }
        };

        $collection = new class extends Collection {
            /**
             * @return never
             *
             * @throws \LogicException
             */
            #[\Override]
            public function toArray(): never
            {
                throw new \LogicException('Not arrayable.');
            }
        };

        $record = (new RedactSecrets)($this->record(
            'Rejected 482915',
            ['secret' => $throwing, 'code' => ['nested' => $collection], 'destination' => '+447700900123'],
            ['otp' => $throwing],
        ));

        self::assertSame(['secret' => '[redacted]', 'code' => '[redacted]', 'destination' => '[redacted]'], $record->context);
        self::assertSame(['otp' => '[redacted]'], $record->extra);
        self::assertSame('Rejected 482915', $record->message);
    }

    /**
     * @return void
     */
    public function testKeepsTheRestOfTheRecord(): void
    {
        $original = $this->record('Verification failed.', [], []);

        $record = (new RedactSecrets)($original);

        self::assertSame('mfa', $record->channel);
        self::assertSame(Level::Warning, $record->level);
        self::assertSame($original->datetime, $record->datetime);
        self::assertSame('Verification failed.', $record->message);
    }

    /**
     * @param  string  $message
     * @param  array<array-key, mixed>  $context
     * @param  array<array-key, mixed>  $extra
     * @return \Monolog\LogRecord
     */
    private function record(string $message, array $context, array $extra): LogRecord
    {
        return new LogRecord(new \DateTimeImmutable, 'mfa', Level::Warning, $message, $context, $extra);
    }
}
