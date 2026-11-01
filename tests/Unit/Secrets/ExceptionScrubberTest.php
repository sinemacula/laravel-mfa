<?php

declare(strict_types = 1);

namespace Tests\Unit\Secrets;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Secrets\ExceptionScrubber;
use SineMacula\Laravel\Mfa\Secrets\RevealedSecret;
use Tests\Fixtures\Secrets\ForgedTrace;
use Tests\Fixtures\Secrets\RecordedTrace;

/**
 * Tests for `ExceptionScrubber`: every argument of a frame that touches the
 * package is redacted, every value the package passed on or a frame marked as
 * sensitive is redacted from every other frame, other frames keep the rest of
 * their arguments with the secrets in them redacted, provisioning URIs leave
 * the messages, and every exception in the chain is scrubbed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ExceptionScrubber::class)]
final class ExceptionScrubberTest extends TestCase
{
    /** @var string A TOTP secret. */
    private const string SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';

    /** @var string A delivered code. */
    private const string CODE = '482915';

    /** @var string A file of the application's. */
    private const string APPLICATION_FILE = '/app/Http/Controllers/VerifyController.php';

    /** @var string A file of a dependency's. */
    private const string VENDOR_FILE = '/app/vendor/laravel/framework/src/Illuminate/Support/Facades/Facade.php';

    /**
     * Every argument of a call into one of the package's classes is redacted,
     * and its string form shows none of them.
     *
     * @return void
     */
    public function testRedactsEveryArgumentOfACallIntoThePackage(): void
    {
        $exception = ForgedTrace::onto(new \RuntimeException('Verification failed.'), [
            $this->frame(self::APPLICATION_FILE, MfaManager::class, 'verify', ['totp', self::CODE]),
        ]);

        ExceptionScrubber::scrub($exception);

        self::assertSame(['[redacted]', '[redacted]'], $this->arguments($exception, 0));
        self::assertStringNotContainsString(self::CODE, $exception->getTraceAsString());
    }

    /**
     * Every argument of a call made from one of the package's files is
     * redacted, a call to a PHP function included.
     *
     * @return void
     */
    public function testRedactsEveryArgumentOfACallThePackageMakes(): void
    {
        $exception = ForgedTrace::onto(new \RuntimeException('Hashing failed.'), [
            $this->frame(ForgedTrace::packageFile('Drivers/TotpDriver.php'), null, 'hash_hmac', ['sha1', '00000001', self::SECRET]),
        ]);

        ExceptionScrubber::scrub($exception);

        self::assertSame(['[redacted]', '[redacted]', '[redacted]'], $this->arguments($exception, 0));
        self::assertStringNotContainsString(self::SECRET, $exception->getTraceAsString());
    }

    /**
     * Arguments of a frame that does not touch the package are kept, apart from
     * the secrets in them.
     *
     * @return void
     */
    public function testKeepsTheArgumentsOfOtherFramesApartFromTheirSecrets(): void
    {
        $exception = ForgedTrace::onto(new \RuntimeException('Request failed.'), [
            $this->frame(self::APPLICATION_FILE, 'App\Http\Controllers\VerifyController', 'store', [
                'harmless',
                42,
                new RevealedSecret(self::SECRET),
                'otpauth://totp/Acme?secret=' . self::SECRET,
                ['secret' => self::SECRET, 'label' => 'Phone'],
            ]),
        ]);

        ExceptionScrubber::scrub($exception);

        self::assertSame(['harmless', 42, '[redacted]', '[redacted]', ['secret' => '[redacted]', 'label' => 'Phone']], $this->arguments($exception, 0));
    }

    /**
     * A file beside the package's source directory, whose path only starts like
     * it, is not the package's.
     *
     * @return void
     */
    public function testKeepsTheArgumentsOfAFileBesideThePackage(): void
    {
        $beside = rtrim(ForgedTrace::packageFile(''), DIRECTORY_SEPARATOR) . '-copy' . DIRECTORY_SEPARATOR . 'Helper.php';

        $exception = ForgedTrace::onto(new \RuntimeException('Request failed.'), [
            $this->frame($beside, null, 'strlen', ['harmless']),
        ]);

        ExceptionScrubber::scrub($exception);

        self::assertSame(['harmless'], $this->arguments($exception, 0));
    }

    /**
     * A frame without arguments, as PHP records with
     * `zend.exception_ignore_args` on, or with arguments that are not a list,
     * is kept as it is.
     *
     * @return void
     */
    public function testKeepsAFrameWithoutArguments(): void
    {
        $frames = [
            ['file' => self::APPLICATION_FILE, 'line' => 12, 'class' => MfaManager::class, 'type' => '::', 'function' => 'verify'],
            ['file' => self::APPLICATION_FILE, 'line' => 14, 'class' => MfaManager::class, 'type' => '::', 'function' => 'verify', 'args' => self::CODE],
        ];

        $exception = ForgedTrace::onto(new \RuntimeException('Verification failed.'), $frames);

        ExceptionScrubber::scrub($exception);

        self::assertSame($frames, $exception->getTrace());
    }

    /**
     * A chain whose previous exceptions loop back is scrubbed once each, and
     * the walk ends.
     *
     * @return void
     */
    public function testStopsAtALoopInTheChain(): void
    {
        $first  = ForgedTrace::onto(new \RuntimeException('First.'), [$this->frame(self::APPLICATION_FILE, MfaManager::class, 'verify', [self::CODE])]);
        $second = ForgedTrace::onto(new \RuntimeException('Second.', 0, $first), [$this->frame(self::APPLICATION_FILE, MfaManager::class, 'verify', [self::CODE])]);

        (new \ReflectionProperty(\Exception::class, 'previous'))->setValue($first, $second);

        ExceptionScrubber::scrub($second);

        self::assertSame(['[redacted]'], $this->arguments($first, 0));
        self::assertSame(['[redacted]'], $this->arguments($second, 0));
    }

    /**
     * Every previous exception in the chain is scrubbed too, an error included.
     *
     * @return void
     */
    public function testScrubsEveryExceptionInTheChain(): void
    {
        $error = ForgedTrace::onto(new \Error('Decryption failed.'), [
            $this->frame(self::APPLICATION_FILE, MfaManager::class, 'verify', [self::CODE]),
        ]);

        $exception = ForgedTrace::onto(new \RuntimeException('Verification failed.', 0, $error), [
            $this->frame(self::APPLICATION_FILE, MfaManager::class, 'verify', [self::CODE]),
        ]);

        ExceptionScrubber::scrub($exception);

        self::assertSame(['[redacted]'], $this->arguments($exception, 0));
        self::assertSame(['[redacted]'], $this->arguments($error, 0));
    }

    /**
     * A value passed into the package is redacted from every other frame that
     * recorded it, in a nested argument too, as a facade's frame records it.
     *
     * @return void
     */
    public function testRedactsAValuePassedIntoThePackageFromEveryFrame(): void
    {
        $exception = ForgedTrace::onto(new \RuntimeException('Verification failed.'), [
            $this->frame(self::VENDOR_FILE, 'Illuminate\Hashing\HashManager', 'check', [self::CODE, 'hashed']),
            $this->frame(self::VENDOR_FILE, MfaManager::class, 'verify', ['totp', self::CODE]),
            $this->frame(self::APPLICATION_FILE, 'Illuminate\Support\Facades\Facade', '__callStatic', ['verify', ['totp', self::CODE]]),
        ]);

        ExceptionScrubber::scrub($exception);

        self::assertSame(['[redacted]', 'hashed'], $this->arguments($exception, 0));
        self::assertSame(['verify', ['[redacted]', '[redacted]']], $this->arguments($exception, 2));
        self::assertStringNotContainsString(self::CODE, $exception->getTraceAsString());
    }

    /**
     * A string containing a value the package passed on is redacted whole when
     * the value is six characters or more, and kept when it is shorter.
     *
     * @return void
     */
    public function testRedactsAStringContainingAValuePassedOnOfSixCharactersOrMore(): void
    {
        $exception = ForgedTrace::onto(new \RuntimeException('Encryption failed.'), [
            $this->frame(self::VENDOR_FILE, 'Illuminate\Encryption\Encrypter', 'encrypt', ['s:32:"' . self::SECRET . '";', 'a sms reminder', 'totp-' . self::CODE]),
            $this->frame(ForgedTrace::packageFile('Drivers/TotpDriver.php'), null, 'encrypt', [self::SECRET, 'sms']),
        ]);

        ExceptionScrubber::scrub($exception);

        self::assertSame(['[redacted]', 'a sms reminder', 'totp-' . self::CODE], $this->arguments($exception, 0));
    }

    /**
     * A value any frame marks as sensitive is redacted from every other frame,
     * when PHP records the trace for real.
     *
     * @return void
     */
    public function testRedactsAValueMarkedSensitiveFromEveryFrameOfARealTrace(): void
    {
        $check = static function (string $code): never {
            throw new \RuntimeException('The code store is unavailable for a code of ' . strlen($code) . ' characters.');
        };

        $exception = RecordedTrace::thrownBy(static function () use ($check): void {
            (static function (#[\SensitiveParameter] string $code) use ($check): void {
                $check($code);
            })(self::CODE);
        });

        self::assertContains(self::CODE, RecordedTrace::strings($exception));

        ExceptionScrubber::scrub($exception);

        self::assertNotContains(self::CODE, RecordedTrace::strings($exception));
        self::assertStringNotContainsString(self::CODE, $exception->getTraceAsString());
    }

    /**
     * The plaintext of a secret value in one frame is redacted from every other
     * frame.
     *
     * @return void
     */
    public function testRedactsThePlaintextOfASecretValueFromEveryFrame(): void
    {
        $exception = ForgedTrace::onto(new \RuntimeException('Encoding failed.'), [
            $this->frame(self::VENDOR_FILE, null, 'json_encode', [['secret_value' => self::SECRET]]),
            $this->frame(self::APPLICATION_FILE, 'App\Http\Controllers\EnrollController', 'respond', [new RevealedSecret(self::SECRET)]),
        ]);

        ExceptionScrubber::scrub($exception);

        self::assertSame([['secret_value' => '[redacted]']], $this->arguments($exception, 0));
        self::assertSame(['[redacted]'], $this->arguments($exception, 1));
    }

    /**
     * A value passed on in one exception of the chain is redacted from the
     * others.
     *
     * @return void
     */
    public function testRedactsAValuePassedOnAcrossTheChain(): void
    {
        $previous = ForgedTrace::onto(new \RuntimeException('Hashing failed.'), [
            $this->frame(self::VENDOR_FILE, MfaManager::class, 'verify', [self::CODE]),
        ]);

        $exception = ForgedTrace::onto(new \RuntimeException('Verification failed.', 0, $previous), [
            $this->frame(self::APPLICATION_FILE, 'App\Http\Controllers\VerifyController', 'store', [self::CODE]),
        ]);

        ExceptionScrubber::scrub($exception);

        self::assertSame(['[redacted]'], $this->arguments($exception, 0));
    }

    /**
     * Empty strings and redaction markers the package passed on are not treated
     * as values to redact elsewhere.
     *
     * @return void
     */
    public function testKeepsEmptyStringsAndMarkersElsewhere(): void
    {
        $exception = ForgedTrace::onto(new \RuntimeException('Verification failed.'), [
            $this->frame(self::VENDOR_FILE, null, 'implode', ['', ['[redacted]', 'kept']]),
            $this->frame(self::VENDOR_FILE, MfaManager::class, 'verify', ['', '[redacted]']),
        ]);

        ExceptionScrubber::scrub($exception);

        self::assertSame(['', ['[redacted]', 'kept']], $this->arguments($exception, 0));
    }

    /**
     * Values nested deeper than the walk reaches are not collected, and the
     * walk ends on a recursive argument.
     *
     * @return void
     */
    public function testStopsCollectingAtTheDeepestLevel(): void
    {
        $recursive         = ['code' => 'kept'];
        $recursive['self'] = &$recursive;

        $exception = ForgedTrace::onto(new \RuntimeException('Verification failed.'), [
            $this->frame(self::VENDOR_FILE, null, 'strlen', ['shallow-value', 'deep-value']),
            $this->frame(self::VENDOR_FILE, MfaManager::class, 'verify', [$this->nested('deep-value', 10), $recursive, $this->nested('shallow-value', 9)]),
        ]);

        ExceptionScrubber::scrub($exception);

        self::assertSame(['[redacted]', 'deep-value'], $this->arguments($exception, 0));
    }

    /**
     * A provisioning URI in the message of the exception and of a previous one
     * is redacted, and a message without one is kept.
     *
     * @return void
     */
    public function testRedactsProvisioningUrisInMessages(): void
    {
        $error     = new \Error('Rendering otpauth://totp/Acme?secret=' . self::SECRET . ' failed.');
        $exception = new \RuntimeException('QR code for otpauth://totp/Acme?secret=' . self::SECRET, 0, $error);
        $kept      = new \RuntimeException('Verification failed.');

        ExceptionScrubber::scrub($exception);
        ExceptionScrubber::scrub($kept);

        self::assertSame('QR code for [redacted]', $exception->getMessage());
        self::assertSame('Rendering [redacted] failed.', $error->getMessage());
        self::assertSame('Verification failed.', $kept->getMessage());
    }

    /**
     * Scrubbing twice changes nothing more.
     *
     * @return void
     */
    public function testScrubbingIsIdempotent(): void
    {
        $exception = ForgedTrace::onto(new \RuntimeException('Verification failed.'), [
            $this->frame(self::APPLICATION_FILE, MfaManager::class, 'verify', [self::CODE]),
        ]);

        ExceptionScrubber::scrub($exception);

        $once = $exception->getTrace();

        ExceptionScrubber::scrub($exception);

        self::assertSame($once, $exception->getTrace());
    }

    /**
     * A trace frame.
     *
     * @param  string  $file
     * @param  ?string  $class
     * @param  string  $function
     * @param  list<mixed>  $arguments
     * @return array<string, mixed>
     */
    private function frame(string $file, ?string $class, string $function, array $arguments): array
    {
        $frame = ['file' => $file, 'line' => 12, 'function' => $function, 'args' => $arguments];

        return $class === null ? $frame : [...$frame, 'class' => $class, 'type' => '::'];
    }

    /**
     * The value, nested in as many lists.
     *
     * @param  string  $value
     * @param  int  $levels
     * @return array<int, mixed>
     */
    private function nested(string $value, int $levels): array
    {
        $nested = [$value];

        for ($level = 1; $level < $levels; $level++) {
            $nested = [$nested];
        }

        return $nested;
    }

    /**
     * The arguments recorded in a frame of the exception's trace.
     *
     * @param  \Throwable  $throwable
     * @param  int  $frame
     * @return mixed
     */
    private function arguments(\Throwable $throwable, int $frame): mixed
    {
        return $throwable->getTrace()[$frame]['args'] ?? null;
    }
}
