<?php

declare(strict_types = 1);

namespace Tests\Unit\Secrets;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Secrets\Redactor;
use SineMacula\Laravel\Mfa\Secrets\RevealedSecret;
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
    private const string SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';

    /**
     * Keys naming secrets, codes and destinations, spelt as code and logs
     * spell them.
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
        yield 'provisioning URI' => ['provisioning_uri'];
        yield 'otpauth URI' => ['otpauthUri'];
    }

    /**
     * A value under a key naming a secret, a code or a destination is
     * redacted, whatever it is.
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
     * A secret value is redacted under any key, and so is a sensitive
     * parameter value.
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
     * Values of any other kind are kept as they are, and a list's numeric keys
     * are never read as names.
     *
     * @return void
     */
    public function testKeepsOtherValues(): void
    {
        $object = new \stdClass;

        self::assertSame([12, 1.5, true, null, $object], Redactor::redact([12, 1.5, true, null, $object]));
        self::assertSame($object, Redactor::value($object));
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
}
