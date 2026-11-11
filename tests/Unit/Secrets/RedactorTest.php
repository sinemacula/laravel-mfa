<?php

declare(strict_types = 1);

namespace Tests\Unit\Secrets;

use Illuminate\Contracts\Support\Arrayable;
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
use Tests\Fixtures\Codes\CodeMessages;
use Tests\Fixtures\Secrets\ForgedTrace;
use Tests\Fixtures\Secrets\RefusesToBeLogged;

/**
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
     * Spelt as code and logs spell them.
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
        yield 'grant' => ['grant'];
        yield 'enrolment grant' => ['enrollment_grant'];
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
     * Whatever the value is.
     *
     * @param  string  $key
     * @return void
     */
    #[DataProvider('sensitiveKeys')]
    public function testRedactsTheValueOfAKeyNamingASecret(string $key): void
    {
        self::assertSame([$key => '[redacted]'], self::redact([$key => self::SECRET]));
        self::assertSame([$key => '[redacted]'], self::redact([$key => ['123456', '654321']]));
    }

    /**
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
     * kept.
     *
     * @param  string  $key
     * @return void
     */
    #[DataProvider('ordinaryKeys')]
    public function testKeepsTheValueOfAnyOtherKey(string $key): void
    {
        self::assertSame([$key => 'value'], self::redact([$key => 'value']));
    }

    /**
     * The shape of the values is kept.
     *
     * @return void
     */
    public function testRedactsAtAnyDepth(): void
    {
        self::assertSame(
            ['factor' => ['id' => '01J0', 'type' => 'sms', 'destination' => '[redacted]'], 'attempt' => 2, 'items' => ['first', 'second']],
            self::redact(['factor' => ['id' => '01J0', 'type' => 'sms', 'destination' => '+447700900123'], 'attempt' => 2, 'items' => ['first', 'second']]),
        );
    }

    /**
     * A sensitive parameter value too.
     *
     * @return void
     */
    public function testRedactsSecretValuesUnderAnyKey(): void
    {
        self::assertSame(
            ['shown' => '[redacted]', 'parameter' => '[redacted]', 'list' => ['[redacted]']],
            self::redact([
                'shown'     => new RevealedSecret(self::SECRET),
                'parameter' => new \SensitiveParameterValue(self::SECRET),
                'list'      => [new RevealedSecret(self::SECRET)],
            ]),
        );
    }

    /**
     * In any case, and the rest of the string is kept.
     *
     * @return void
     */
    public function testRedactsProvisioningUrisInStrings(): void
    {
        self::assertSame('Scan [redacted] to finish', Redactor::redactString('Scan otpauth://totp/Acme:ben?issuer=Acme&secret=' . self::SECRET . ' to finish'));
        self::assertSame('[redacted]', Redactor::redactString('OTPAUTH://totp/Acme?secret=' . self::SECRET));
        self::assertSame('[redacted]', Redactor::redactString('otpauth-migration://offline?data=' . self::SECRET));
        self::assertSame(['note' => 'Scanned [redacted]'], self::redact(['note' => 'Scanned otpauth://totp/Acme?secret=' . self::SECRET]));
    }

    /**
     * @return void
     */
    public function testKeepsAStringWithoutAProvisioningUri(): void
    {
        self::assertSame('Sent a code to the phone ending 0123', Redactor::redactString('Sent a code to the phone ending 0123'));
    }

    /**
     * A list's numeric keys are never read as names.
     *
     * @return void
     */
    public function testKeepsScalars(): void
    {
        self::assertSame([12, 1.5, true, null, 'Phone'], self::redact([12, 1.5, true, null, 'Phone']));
    }

    /**
     * Keyed by its class.
     *
     * @return void
     */
    public function testRedactsThePublicPropertiesOfAnObject(): void
    {
        $factor = (object) ['type' => 'sms', 'destination' => '+447700900123', 'secret' => self::SECRET];

        self::assertSame(
            ['factor' => [\stdClass::class => ['type' => 'sms', 'destination' => '[redacted]', 'secret' => '[redacted]']]],
            self::redact(['factor' => $factor]),
        );
    }

    /**
     * So a secret value in it is redacted rather than refusing to be encoded.
     *
     * @return void
     */
    public function testRedactsTheArrayFormOfACollection(): void
    {
        $codes = new Collection([new RevealedSecret(self::SECRET), 'kept']);

        self::assertSame([Collection::class => ['[redacted]', 'kept']], self::redact(['value' => $codes])['value']);
    }

    /**
     * A JSON object becomes its JSON form and a string object its string form,
     * each redacted.
     *
     * @return void
     */
    public function testRedactsTheJsonAndStringFormsOfAnObject(): void
    {
        $json = new class implements \JsonSerializable {
            /**
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
             * @return string
             */
            #[\Override]
            public function __toString(): string
            {
                return 'Scan otpauth://totp/Acme?secret=' . RedactorTest::SECRET;
            }
        };

        self::assertSame([get_debug_type($json) => ['code' => '[redacted]', 'label' => 'Phone']], self::redact(['value' => $json])['value']);
        self::assertSame([get_debug_type($string) => 'Scan [redacted]'], self::redact(['value' => $string])['value']);
    }

    /**
     * Errors included; what it holds is not read another way, and the values
     * beside it are still normalised.
     *
     * @return void
     */
    public function testLogsAnObjectThatRefusesItsFormAsItsClassAlone(): void
    {
        $arrayable = new class implements Arrayable {
            /**
             * @return array<string, string>
             *
             * @throws \LogicException
             */
            #[\Override]
            public function toArray(): array
            {
                throw new \LogicException('Refused.');
            }
        };

        $string = new class implements \Stringable {
            /**
             * With an error rather than an exception.
             *
             * @return string
             *
             * @throws \TypeError
             */
            #[\Override]
            public function __toString(): string
            {
                throw new \TypeError('Refused.');
            }
        };

        $normalized = Redactor::normalize([
            'arrayable' => $arrayable,
            'json'      => new RefusesToBeLogged,
            'string'    => $string,
            'beside'    => (object) ['label' => 'Phone'],
        ]);

        self::assertSame(
            [
                'arrayable' => [get_debug_type($arrayable) => '[unserializable]'],
                'json'      => [RefusesToBeLogged::class => '[unserializable]'],
                'string'    => [get_debug_type($string) => '[unserializable]'],
                'beside'    => [\stdClass::class => ['label' => 'Phone']],
            ],
            $normalized,
        );
        self::assertStringNotContainsString(RefusesToBeLogged::VALUE, (string) json_encode($normalized));
    }

    /**
     * @return void
     */
    public function testKeepsDatesAndEnums(): void
    {
        $date = new \DateTimeImmutable('2026-11-01T09:00:00Z');

        self::assertSame(['at' => $date, 'case' => FailureReason::LOCKED], self::redact(['at' => $date, 'case' => FailureReason::LOCKED]));
    }

    /**
     * So a recursive value ends; a string at that depth is still redacted.
     *
     * @return void
     */
    public function testTruncatesBelowTheDeepestLevel(): void
    {
        $recursive         = ['label' => 'Phone'];
        $recursive['self'] = &$recursive;

        $redacted = self::redact(['context' => $recursive]);

        $current = $redacted['context'];

        for ($level = 1; $level < Redactor::MAX_DEPTH; $level++) {
            self::assertIsArray($current);
            self::assertSame('Phone', $current['label']);

            $current = $current['self'];
        }

        self::assertSame(['label' => 'Phone', 'self' => '[truncated]'], $current);

        self::assertSame($this->nested('[truncated]', 11), self::redact($this->nested([], 11)));
        self::assertSame($this->nested([], 10), self::redact($this->nested([], 10)));
        self::assertSame($this->nested('[truncated]', 11), self::redact($this->nested(new \stdClass, 11)));
        self::assertSame($this->nested([\stdClass::class => '[truncated]'], 10), self::redact($this->nested(new \stdClass, 10)));
        self::assertSame($this->nested('[redacted]', 11), self::redact($this->nested('otpauth://totp/Acme?secret=' . self::SECRET, 11)));
    }

    /**
     * @return void
     */
    public function testKeepsTheFirstThousandEntries(): void
    {
        $redacted = self::redact(range(1, 1001));

        self::assertCount(1001, $redacted);
        self::assertSame(1000, $redacted[999]);
        self::assertSame('[truncated]', $redacted['...']);
        self::assertCount(1000, self::redact(range(1, 1000)));
    }

    /**
     * As deep as the walk reaches and no deeper, and to their first thousand
     * entries.
     *
     * @return void
     */
    public function testBoundsATracesArgumentsAsDeepAndAsWideAsLoggedValues(): void
    {
        self::assertSame($this->nested([], 10), Redactor::arguments($this->nested([], 10)));
        self::assertSame($this->nested('[truncated]', 11), Redactor::arguments($this->nested([], 11)));

        $arguments = Redactor::arguments(range(1, 1001));

        self::assertCount(1001, $arguments);
        self::assertSame(1000, $arguments[999]);
        self::assertArrayNotHasKey(1000, $arguments);
        self::assertSame('[truncated]', $arguments['...']);
    }

    /**
     * One at the deepest level is still named, holding the marker.
     *
     * @return void
     */
    public function testNormalizesAnObjectBelowTheDeepestLevelToTheMarker(): void
    {
        self::assertSame($this->nested('[truncated]', 11), Redactor::normalize($this->nested(new \stdClass, 11)));
        self::assertSame($this->nested([\stdClass::class => '[truncated]'], 10), Redactor::normalize($this->nested(new \stdClass, 10)));
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

        $redacted = self::redact(['exception' => $exception]);

        self::assertSame($exception, $redacted['exception']);
        self::assertSame(['[redacted]'], $exception->getTrace()[0]['args'] ?? null);
    }

    /**
     * Objects are kept; a collected value goes when equal or from six
     * characters, a known one whatever its length.
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
     * Nested too; a job sending another message is kept in a trace.
     *
     * @return void
     */
    public function testRedactsCodeMessages(): void
    {
        $message = (new MfaCodeMessage('482915', 10))->to('ada@example.test');
        $other   = new SendQueuedMailable(new Mailable);

        $handed = CodeMessages::to('ada@example.test', '482915');

        self::assertSame(['[redacted]', ['[redacted]'], $other, '[redacted]'], Redactor::arguments([$message, [new SendQueuedMailable($message)], $other, $handed]));
        self::assertSame(
            ['message' => '[redacted]', 'nested' => ['[redacted]'], 'handed' => '[redacted]'],
            self::redact(['message' => $message, 'nested' => [new SendQueuedMailable($message)], 'handed' => $handed]),
        );
    }

    /**
     * Secret values, code messages, exceptions, dates, enums and scalars are
     * kept as they are.
     *
     * @return void
     */
    public function testNormalizesObjectsIntoTheirLoggedForm(): void
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
            Redactor::normalize([
                'payload' => (object) ['code' => '482915', 'inner' => new Collection(['kept'])],
                'kept'    => [$secret, $message, $exception, $date, FailureReason::LOCKED, 'text', 42],
            ]),
        );

        self::assertSame($this->nested('[truncated]', 11), Redactor::normalize($this->nested([], 11)));
        self::assertSame($this->nested([\stdClass::class => '[truncated]'], 10), Redactor::normalize($this->nested(new \stdClass, 10)));
        self::assertCount(1001, Redactor::normalize(range(1, 1001)));
        self::assertSame('[truncated]', Redactor::normalize(range(1, 1001))['...']);
    }

    /**
     * Its own level and its form's, so the fifth one down still keeps what it
     * holds.
     *
     * @return void
     */
    public function testAnObjectInAnObjectTakesTwoLevels(): void
    {
        $value    = 'kept';
        $expected = 'kept';

        for ($level = 0; $level < 5; $level++) {
            $value    = (object) ['inner' => $value];
            $expected = [\stdClass::class => ['inner' => $expected]];
        }

        self::assertSame(['context' => $expected], Redactor::normalize(['context' => $value]));
    }

    /**
     * A logged exception among them is scrubbed of the values given.
     *
     * @return void
     */
    public function testRedactsNormalizedValues(): void
    {
        $exception = new \RuntimeException('Rejected 482915');

        self::assertSame(
            ['payload' => [\stdClass::class => ['code' => '[redacted]']], 'exception' => $exception, 'deep' => $this->nested('[truncated]', 10)],
            Redactor::redactNormalized(
                ['payload' => [\stdClass::class => ['code' => '482915']], 'exception' => $exception, 'deep' => $this->nested([], 10)],
                SensitiveValues::known('482915'),
            ),
        );
        self::assertSame('Rejected [redacted]', $exception->getMessage());
    }

    /**
     * The strings beside it are kept, and a log's own strings are not matched
     * against the values.
     *
     * @return void
     */
    public function testScrubsALoggedExceptionOfTheValuesGiven(): void
    {
        $exception = new \RuntimeException('Rejected 482915', 0, new \LogicException('Previously 482915'));

        $redacted = self::redact(['exception' => $exception, 'note' => 'Rejected 482915'], SensitiveValues::inArguments(['482915'], true));

        self::assertSame(['exception' => $exception, 'note' => 'Rejected 482915'], $redacted);
        self::assertSame('Rejected [redacted]', $exception->getMessage());
        self::assertSame('Previously [redacted]', $exception->getPrevious()?->getMessage());
    }

    /**
     * Every provisioning URI too.
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
     * Normalised and redacted, as a log record's values are.
     *
     * @param  array<array-key, mixed>  $values
     * @param  ?\SineMacula\Laravel\Mfa\Secrets\SensitiveValues  $sensitive
     * @return array<array-key, mixed>
     */
    private static function redact(array $values, ?SensitiveValues $sensitive = null): array
    {
        return Redactor::redactNormalized(Redactor::normalize($values), $sensitive ?? SensitiveValues::none());
    }

    /**
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
