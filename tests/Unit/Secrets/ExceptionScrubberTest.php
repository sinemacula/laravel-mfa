<?php

declare(strict_types = 1);

namespace Tests\Unit\Secrets;

use Illuminate\Mail\SendQueuedMailable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Codes\MfaCodeMessage;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Secrets\ExceptionScrubber;
use SineMacula\Laravel\Mfa\Secrets\RevealedSecret;
use SineMacula\Laravel\Mfa\Secrets\SensitiveValues;
use Tests\Fixtures\Secrets\ForgedTrace;
use Tests\Fixtures\Secrets\RecordedTrace;

/**
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
     * Its string form shows none of them either.
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
     * A call to a PHP function included.
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
     * A path that only starts like the package's source directory is not the
     * package's.
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
     * As PHP records with `zend.exception_ignore_args` on, or with arguments
     * that are not a list.
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
     * Each exception is scrubbed once, and the walk ends.
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
     * An error included.
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
     * In a nested argument too, as a facade's frame records it.
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
     * Redacted whole when the value is six characters or more, and kept when it
     * is shorter.
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
     * When PHP records the trace for real.
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
     * Empty strings and redaction markers the package passed on are not values
     * to redact elsewhere.
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
     * The walk also ends on a recursive argument.
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
     * In the exception's message and a previous one's; a message without one is
     * kept.
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
     * A value recorded as sensitive is replaced at each occurrence in every
     * message, and a message that is a shorter value goes whole.
     *
     * @return void
     */
    public function testRedactsTheValuesCollectedFromEveryMessageOfTheChain(): void
    {
        $previous = ForgedTrace::onto(new \RuntimeException('Hashing ' . self::CODE . ' failed.'), [
            ['file' => self::VENDOR_FILE, 'line' => 10, 'function' => 'hash'],
            $this->frame(self::VENDOR_FILE, MfaManager::class, 'verify', ['totp', self::CODE]),
        ]);

        $exception = ForgedTrace::onto(new \RuntimeException('Verification of ' . self::CODE . ' failed, again ' . self::CODE . '.', 0, $previous), [
            $this->frame(self::APPLICATION_FILE, 'App\Http\Controllers\VerifyController', 'store', []),
        ]);

        $short = ForgedTrace::onto(new \RuntimeException('totp'), [
            $this->frame(self::VENDOR_FILE, MfaManager::class, 'verify', ['totp']),
        ]);

        ExceptionScrubber::scrub($exception);
        ExceptionScrubber::scrub($short);

        self::assertSame('Verification of [redacted] failed, again [redacted].', $exception->getMessage());
        self::assertSame('Hashing [redacted] failed.', $previous->getMessage());
        self::assertSame('[redacted]', $short->getMessage());
    }

    /**
     * Whether PHP records call arguments in a trace, as in development, or not,
     * as in production.
     *
     * @return iterable<string, array{bool}>
     */
    public static function traceArguments(): iterable
    {
        yield 'arguments recorded' => [true];
        yield 'arguments ignored' => [false];
    }

    /**
     * From every message and frame, whatever their length; empty and missing
     * values are ignored.
     *
     * @param  bool  $arguments
     * @return void
     */
    #[DataProvider('traceArguments')]
    public function testRedactsTheValuesGivenWhetherOrNotArgumentsWereRecorded(bool $arguments): void
    {
        $exception = RecordedTrace::thrownBy(static function (): void {
            (static function (string $body, string $to): void {
                throw new \RuntimeException('Refused "' . $body . '" for ' . $to, 0, new \LogicException('Upstream: ' . $to));
            })('Your code is 4821', '+447700900123');
        }, $arguments);

        ExceptionScrubber::scrub($exception, '4821', '+447700900123', '', null);

        self::assertSame('Refused "Your code is [redacted]" for [redacted]', $exception->getMessage());
        self::assertSame('Upstream: [redacted]', $exception->getPrevious()?->getMessage());

        foreach (RecordedTrace::strings($exception) as $string) {
            self::assertStringNotContainsString('4821', $string);
            self::assertStringNotContainsString('+447700900123', $string);
        }
    }

    /**
     * Nested or queued too; its code and recipient leave every other frame and
     * message, whatever their length.
     *
     * @return void
     */
    public function testRedactsACodeMessageAndWhatItCarries(): void
    {
        $message = (new MfaCodeMessage('4821', 10))->to('ada@example.test');

        $exception = ForgedTrace::onto(new \RuntimeException('The relay refused ada@example.test.'), [
            $this->frame(self::VENDOR_FILE, 'Symfony\Component\Mime\Email', 'html', ['<p>Your code is 4821</p>']),
            $this->frame(self::VENDOR_FILE, 'Illuminate\Mail\Mailer', 'send', [['html' => 'view'], ['message' => $message]]),
            $this->frame(self::VENDOR_FILE, 'Illuminate\Queue\CallQueuedHandler', 'dispatchThroughMiddleware', ['job', new SendQueuedMailable($message)]),
        ]);

        ExceptionScrubber::scrub($exception);

        self::assertSame('The relay refused [redacted].', $exception->getMessage());
        self::assertSame(['[redacted]'], $this->arguments($exception, 0));
        self::assertSame([['html' => 'view'], ['message' => '[redacted]']], $this->arguments($exception, 1));
        self::assertSame(['job', '[redacted]'], $this->arguments($exception, 2));
    }

    /**
     * A known value whatever its length, a collected one only from six
     * characters.
     *
     * @return void
     */
    public function testRedactsTheSensitiveValuesGivenByTheirKind(): void
    {
        $exception = new \RuntimeException('Rejected 4821 and abcd, then 482915', 0, new \LogicException('Previously 4821'));

        ExceptionScrubber::scrubWith($exception, SensitiveValues::known('4821')->with(SensitiveValues::inArguments(['abcd', '482915'], true)));

        self::assertSame('Rejected [redacted] and abcd, then [redacted]', $exception->getMessage());
        self::assertSame('Previously [redacted]', $exception->getPrevious()?->getMessage());
    }

    /**
     * @return void
     */
    public function testReadsTheSensitiveValuesWithoutScrubbing(): void
    {
        $exception = ForgedTrace::onto(new \RuntimeException('Verification of ' . self::CODE . ' failed.'), [
            $this->frame(self::VENDOR_FILE, MfaManager::class, 'verify', [self::CODE]),
        ]);

        $values = ExceptionScrubber::sensitiveValuesOf($exception);

        self::assertTrue($values->matches(self::CODE));
        self::assertSame([self::CODE], $this->arguments($exception, 0));
        self::assertSame('Verification of ' . self::CODE . ' failed.', $exception->getMessage());
    }

    /**
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
     * @param  \Throwable  $throwable
     * @param  int  $frame
     * @return mixed
     */
    private function arguments(\Throwable $throwable, int $frame): mixed
    {
        return $throwable->getTrace()[$frame]['args'] ?? null;
    }
}
