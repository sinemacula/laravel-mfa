<?php

declare(strict_types = 1);

namespace Tests\Unit\Secrets;

use Monolog\Level;
use Monolog\LogRecord;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Secrets\RedactSecrets;
use SineMacula\Laravel\Mfa\Secrets\RevealedSecret;

/**
 * Tests for the `RedactSecrets` Monolog processor: the message, the context and
 * the extra data of a record are redacted, and nothing else changes.
 *
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
     * The message, the context and the extra data are redacted.
     *
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
     * The channel, level and time of the record are kept.
     *
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
     * A log record.
     *
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
