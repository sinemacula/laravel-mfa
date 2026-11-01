<?php

declare(strict_types = 1);

namespace Tests\Unit\Secrets;

use Illuminate\Mail\Mailable;
use Illuminate\Mail\SendQueuedMailable;
use Illuminate\Support\Collection;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Codes\MfaCodeMessage;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Secrets\Redactor;
use SineMacula\Laravel\Mfa\Secrets\RevealedSecret;
use SineMacula\Laravel\Mfa\Secrets\SensitiveValues;
use Tests\Fixtures\Secrets\ForgedTrace;

/**
 * Tests for `Redactor`: secrets, codes and full destinations are redacted by
 * value and by key, at any depth, and nothing else is touched.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Redactor::class)]
final class RedactorTest extends TestCase
{
    /** @var string A TOTP secret. */
    public const string SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';

    /**
     * Keys naming secrets, codes and destinations, spelt as code and logs spell
     * them.
     *
     * @return iterable<string, array{string}>
     */
    public static function sensitiveKeys(): iterable
    {
        yield 'secret' => ['secret'];
        yield 'secret in capitals' => ['SECRET'];
        yield 'TOTP secret' => ['totp_secret'];
        yield 'code' => ['code'];
        yield 'codes' => ['codes'];
        yield 'one-time password' => ['otp'];
        yield 'one-time code' => ['one_time_code'];
        yield 'recovery code' => ['recovery_code'];
        yield 'recovery codes' => ['recovery_codes'];
        yield 'recovery codes in camel case' => ['recoveryCodes'];
        yield 'recovery codes with hyphens' => ['recovery-codes'];
        yield 'recovery codes with spaces' => ['recovery codes'];
        yield 'destination' => ['destination'];
        yield 'address' => ['address'];
        yield 'email' => ['email'];
        yield 'phone' => ['phone'];
        yield 'phone number' => ['phone_number'];
        yield 'phone number in camel case' => ['phoneNumber'];
        yield 'to' => ['to'];
        yield 'recipient' => ['recipient'];
        yield 'provisioning URI' => ['provisioning_uri'];
        yield 'otpauth URI' => ['otpauthUri'];
    }

    /**
     * A value under a key naming a secret, a code or a destination is redacted,
     * whatever it is.
     *
     * @param  string  $key
     * @return void
     */
    #[DataProvider('sensitiveKeys')]
    public function testRedactsTheValueOfAKeyNamingASecret(string $key): void
    {
        self::assertSame([$key => '[redacted]'], Redactor::redact([$key => self::SECRET]));
        self::assertSame([$key => '[redacted]'], Redactor::redact([$key => ['123456', '654321']]));
    }

    /**
     * Keys that name no secret.
     *
     * @return iterable<string, array{string}>
     */
    public static function ordinaryKeys(): iterable
    {
        yield 'label' => ['label'];
        yield 'status code' => ['status_code'];
        yield 'country code' => ['country_code'];
        yield 'masked destination' => ['masked_destination'];
        yield 'email verified at' => ['email_verified_at'];
        yield 'total' => ['total'];
        yield 'factor id' => ['factor_id'];
    }

    /**
     * A key that only contains a sensitive word, or names something else, is
     * kept with its value.
     *
     * @param  string  $key
     * @return void
     */
    #[DataProvider('ordinaryKeys')]
    public function testKeepsTheValueOfAnyOtherKey(string $key): void
    {
        self::assertSame([$key => 'value'], Redactor::redact([$key => 'value']));
    }

    /**
     * Secrets are redacted at any depth, and the shape of the values is kept.
     *
     * @return void
     */
    public function testRedactsAtAnyDepth(): void
    {
        self::assertSame(
            ['factor' => ['id' => '01J0', 'type' => 'sms', 'destination' => '[redacted]'], 'attempt' => 2, 'items' => ['first', 'second']],
            Redactor::redact(['factor' => ['id' => '01J0', 'type' => 'sms', 'destination' => '+447700900123'], 'attempt' => 2, 'items' => ['first', 'second']]),
        );
    }

    /**
     * A secret value is redacted under any key, and so is a sensitive parameter
     * value.
     *
     * @return void
     */
    public function testRedactsSecretValuesUnderAnyKey(): void
    {
        self::assertSame(
            ['shown' => '[redacted]', 'parameter' => '[redacted]', 'list' => ['[redacted]']],
            Redactor::redact([
                'shown'     => new RevealedSecret(self::SECRET),
                'parameter' => new \SensitiveParameterValue(self::SECRET),
                'list'      => [new RevealedSecret(self::SECRET)],
            ]),
        );
    }

    /**
     * A provisioning URI is redacted wherever it appears in a string, in any
     * case, and the rest of the string is kept.
     *
     * @return void
     */
    public function testRedactsProvisioningUrisInStrings(): void
    {
        self::assertSame('Scan [redacted] to finish', Redactor::redactString('Scan otpauth://totp/Acme:ben?issuer=Acme&secret=' . self::SECRET . ' to finish'));
        self::assertSame('[redacted]', Redactor::redactString('OTPAUTH://totp/Acme?secret=' . self::SECRET));
        self::assertSame('[redacted]', Redactor::redactString('otpauth-migration://offline?data=' . self::SECRET));
        self::assertSame(['note' => 'Scanned [redacted]'], Redactor::redact(['note' => 'Scanned otpauth://totp/Acme?secret=' . self::SECRET]));
    }

    /**
     * A string with no provisioning URI is kept as it is.
     *
     * @return void
     */
    public function testKeepsAStringWithoutAProvisioningUri(): void
    {
        self::assertSame('Sent a code to the phone ending 0123', Redactor::redactString('Sent a code to the phone ending 0123'));
    }

    /**
     * Scalars are kept as they are, and a list's numeric keys are never read as
     * names.
     *
     * @return void
     */
    public function testKeepsScalars(): void
    {
        self::assertSame([12, 1.5, true, null, 'Phone'], Redactor::redact([12, 1.5, true, null, 'Phone']));
    }

    /**
     * A plain object in a log's values becomes its public properties, keyed by
     * its class, with the secrets in them redacted.
     *
     * @return void
     */
    public function testRedactsThePublicPropertiesOfAnObject(): void
    {
        $factor = (object) ['type' => 'sms', 'destination' => '+447700900123', 'secret' => self::SECRET];

        self::assertSame(
            ['factor' => [\stdClass::class => ['type' => 'sms', 'destination' => '[redacted]', 'secret' => '[redacted]']]],
            Redactor::redact(['factor' => $factor]),
        );
    }

    /**
     * A collection becomes its array form, so a secret value in it is redacted
     * rather than refusing to be encoded.
     *
     * @return void
     */
    public function testRedactsTheArrayFormOfACollection(): void
    {
        $codes = new Collection([new RevealedSecret(self::SECRET), 'kept']);

        self::assertSame([Collection::class => ['[redacted]', 'kept']], Redactor::value($codes));
    }

    /**
     * An object that encodes itself as JSON becomes its JSON form, and a string
     * object its string form, each with the secrets in it redacted.
     *
     * @return void
     */
    public function testRedactsTheJsonAndStringFormsOfAnObject(): void
    {
        $json = new class implements \JsonSerializable {
            /**
             * The JSON form.
             *
             * @return array<string, string>
             */
            #[\Override]
            public function jsonSerialize(): array
            {
                return ['code' => '482915', 'label' => 'Phone'];
            }
        };

        $string = new class implements \Stringable {
            /**
             * The string form.
             *
             * @return string
             */
            #[\Override]
            public function __toString(): string
            {
                return 'Scan otpauth://totp/Acme?secret=' . RedactorTest::SECRET;
            }
        };

        self::assertSame([get_debug_type($json) => ['code' => '[redacted]', 'label' => 'Phone']], Redactor::value($json));
        self::assertSame([get_debug_type($string) => 'Scan [redacted]'], Redactor::value($string));
    }

    /**
     * Dates and enums are kept as they are.
     *
     * @return void
     */
    public function testKeepsDatesAndEnums(): void
    {
        $date = new \DateTimeImmutable('2026-11-01T09:00:00Z');

        self::assertSame(['at' => $date, 'case' => FailureReason::LOCKED], Redactor::redact(['at' => $date, 'case' => FailureReason::LOCKED]));
    }

    /**
     * Arrays and objects deeper than the walk reaches are truncated, so a
     * recursive value ends, and a string at that depth is still redacted.
     *
     * @return void
     */
    public function testTruncatesBelowTheDeepestLevel(): void
    {
        $recursive         = ['label' => 'Phone'];
        $recursive['self'] = &$recursive;

        $redacted = Redactor::redact(['context' => $recursive]);

        $current = $redacted['context'];

        for ($level = 1; $level < Redactor::MAX_DEPTH; $level++) {
            self::assertIsArray($current);
            self::assertSame('Phone', $current['label']);

            $current = $current['self'];
        }

        self::assertSame(['label' => 'Phone', 'self' => '[truncated]'], $current);

        self::assertSame($this->nested('[truncated]', 11), Redactor::redact($this->nested([], 11)));
        self::assertSame($this->nested([], 10), Redactor::redact($this->nested([], 10)));
        self::assertSame($this->nested('[truncated]', 11), Redactor::redact($this->nested(new \stdClass, 11)));
        self::assertSame($this->nested([\stdClass::class => '[truncated]'], 10), Redactor::redact($this->nested(new \stdClass, 10)));
        self::assertSame($this->nested('[redacted]', 11), Redactor::redact($this->nested('otpauth://totp/Acme?secret=' . self::SECRET, 11)));
    }

    /**
     * Only the first thousand entries of an array are kept.
     *
     * @return void
     */
    public function testKeepsTheFirstThousandEntries(): void
    {
        $redacted = Redactor::redact(range(1, 1001));

        self::assertCount(1001, $redacted);
        self::assertSame(1000, $redacted[999]);
        self::assertSame('[truncated]', $redacted['...']);
        self::assertCount(1000, Redactor::redact(range(1, 1000)));
    }

    /**
     * An exception is kept, with its trace scrubbed in place.
     *
     * @return void
     */
    public function testScrubsTheTraceOfAnException(): void
    {
        $exception = ForgedTrace::onto(new \RuntimeException('Verification failed.'), [
            ['file' => '/app/Http/Controllers/VerifyController.php', 'line' => 12, 'class' => RevealedSecret::class, 'type' => '->', 'function' => 'reveal', 'args' => ['123456']],
        ]);

        $redacted = Redactor::redact(['exception' => $exception]);

        self::assertSame($exception, $redacted['exception']);
        self::assertSame(['[redacted]'], $exception->getTrace()[0]['args'] ?? null);
    }

    /**
     * A trace's arguments keep their objects, and lose every string that is a
     * value collected, or contains one of six characters or more, and every
     * string containing a value known to be sensitive, whatever its length.
     *
     * @return void
     */
    public function testRedactsTheSensitiveValuesFromATracesArguments(): void
    {
        $object    = (object) ['secret' => self::SECRET];
        $arguments = [$object, '482915', 'code 482915 sent', 'sms gateway', 'sms', 'harmless', ['secret' => 'x', 'note' => 'otpauth://totp/A?secret=B'], 'Your code is 4821'];
        $values    = SensitiveValues::inArguments(['482915', 'sms'], true)->with(SensitiveValues::known('4821'));

        self::assertSame(
            [$object, '[redacted]', '[redacted]', 'sms gateway', '[redacted]', 'harmless', ['secret' => '[redacted]', 'note' => '[redacted]'], '[redacted]'],
            Redactor::arguments($arguments, $values),
        );

        self::assertSame(['482915'], Redactor::arguments(['482915']));
    }

    /**
     * A code message, or a queued job sending one, is redacted from a trace's
     * arguments and from a log's values, nested in an array too; a job sending
     * another message is kept in a trace.
     *
     * @return void
     */
    public function testRedactsCodeMessages(): void
    {
        $message = (new MfaCodeMessage('482915', 10))->to('ada@example.test');
        $other   = new SendQueuedMailable(new Mailable);

        self::assertSame(['[redacted]', ['[redacted]'], $other], Redactor::arguments([$message, [new SendQueuedMailable($message)], $other]));
        self::assertSame(['message' => '[redacted]', 'nested' => ['[redacted]']], Redactor::redact(['message' => $message, 'nested' => [new SendQueuedMailable($message)]]));
    }

    /**
     * Normalising turns each object into its logged form, keyed by its class,
     * and keeps secret values, code messages, exceptions, dates and enums, and
     * scalars, as they are, bounded as the redaction is.
     *
     * @return void
     */
    public function testNormalisesObjectsIntoTheirLoggedForm(): void
    {
        $secret    = new RevealedSecret(self::SECRET);
        $message   = new MfaCodeMessage('482915', 10);
        $exception = new \RuntimeException('Failed.');
        $date      = new \DateTimeImmutable('2026-11-01');

        self::assertSame(
            [
                'payload' => [\stdClass::class => ['code' => '482915', 'inner' => [Collection::class => ['kept']]]],
                'kept'    => [$secret, $message, $exception, $date, FailureReason::LOCKED, 'text', 42],
            ],
            Redactor::normalise([
                'payload' => (object) ['code' => '482915', 'inner' => new Collection(['kept'])],
                'kept'    => [$secret, $message, $exception, $date, FailureReason::LOCKED, 'text', 42],
            ]),
        );

        self::assertSame($this->nested('[truncated]', 11), Redactor::normalise($this->nested([], 11)));
        self::assertSame($this->nested([\stdClass::class => '[truncated]'], 10), Redactor::normalise($this->nested(new \stdClass, 10)));
        self::assertCount(1001, Redactor::normalise(range(1, 1001)));
        self::assertSame('[truncated]', Redactor::normalise(range(1, 1001))['...']);
    }

    /**
     * Values already normalised are redacted as they are, and a logged
     * exception among them is scrubbed of the values given.
     *
     * @return void
     */
    public function testRedactsNormalisedValues(): void
    {
        $exception = new \RuntimeException('Rejected 482915');

        self::assertSame(
            ['payload' => [\stdClass::class => ['code' => '[redacted]']], 'exception' => $exception, 'deep' => $this->nested('[truncated]', 10)],
            Redactor::redactNormalised(
                ['payload' => [\stdClass::class => ['code' => '482915']], 'exception' => $exception, 'deep' => $this->nested([], 10)],
                SensitiveValues::known('482915'),
            ),
        );
        self::assertSame('Rejected [redacted]', $exception->getMessage());
    }

    /**
     * A logged exception is scrubbed of the sensitive values given too, while
     * the strings beside it are kept, and a log's own strings are not matched
     * against them.
     *
     * @return void
     */
    public function testScrubsALoggedExceptionOfTheValuesGiven(): void
    {
        $exception = new \RuntimeException('Rejected 482915', 0, new \LogicException('Previously 482915'));

        $redacted = Redactor::redact(['exception' => $exception, 'note' => 'Rejected 482915'], SensitiveValues::inArguments(['482915'], true));

        self::assertSame(['exception' => $exception, 'note' => 'Rejected 482915'], $redacted);
        self::assertSame('Rejected [redacted]', $exception->getMessage());
        self::assertSame('Previously [redacted]', $exception->getPrevious()?->getMessage());
    }

    /**
     * A message loses every occurrence of the sensitive values in it, and every
     * provisioning URI.
     *
     * @return void
     */
    public function testRedactsAMessage(): void
    {
        $values = SensitiveValues::known('4821', 'ada@example.test');

        self::assertSame(
            'Sent [redacted] to [redacted] with [redacted]',
            Redactor::redactMessage('Sent 4821 to ada@example.test with otpauth://totp/A?secret=' . self::SECRET, $values),
        );
    }

    /**
     * The value, nested in as many lists.
     *
     * @param  mixed  $value
     * @param  int  $levels
     * @return array<int, mixed>
     */
    private function nested(mixed $value, int $levels): array
    {
        $nested = [$value];

        for ($level = 1; $level < $levels; $level++) {
            $nested = [$nested];
        }

        return $nested;
    }
}
