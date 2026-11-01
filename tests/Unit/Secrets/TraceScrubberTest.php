<?php

declare(strict_types = 1);

namespace Tests\Unit\Secrets;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Secrets\RevealedSecret;
use SineMacula\Laravel\Mfa\Secrets\TraceScrubber;
use Tests\Fixtures\Secrets\ForgedTrace;

/**
 * Tests for `TraceScrubber`: every argument of a frame that touches the
 * package is redacted, other frames keep theirs with the secrets in them
 * redacted, and every exception in the chain is scrubbed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TraceScrubber::class)]
final class TraceScrubberTest extends TestCase
{
    /** @var string A TOTP secret. */
    private const string SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';

    /** @var string A delivered code. */
    private const string CODE = '482915';

    /** @var string A file of the application's. */
    private const string APPLICATION_FILE = '/app/Http/Controllers/VerifyController.php';

    /**
     * Every argument of a call into one of the package's classes is
     * redacted, and its string form shows none of them.
     *
     * @return void
     */
    public function testRedactsEveryArgumentOfACallIntoThePackage(): void
    {
        $exception = ForgedTrace::onto(new \RuntimeException('Verification failed.'), [
            $this->frame(self::APPLICATION_FILE, Mfa::class, 'verify', ['totp', self::CODE]),
        ]);

        TraceScrubber::scrub($exception);

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

        TraceScrubber::scrub($exception);

        self::assertSame(['[redacted]', '[redacted]', '[redacted]'], $this->arguments($exception, 0));
        self::assertStringNotContainsString(self::SECRET, $exception->getTraceAsString());
    }

    /**
     * Arguments of a frame that does not touch the package are kept, apart
     * from the secrets in them.
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

        TraceScrubber::scrub($exception);

        self::assertSame(['harmless', 42, '[redacted]', '[redacted]', ['secret' => '[redacted]', 'label' => 'Phone']], $this->arguments($exception, 0));
    }

    /**
     * A file beside the package's source directory, whose path only starts
     * like it, is not the package's.
     *
     * @return void
     */
    public function testKeepsTheArgumentsOfAFileBesideThePackage(): void
    {
        $beside = rtrim(ForgedTrace::packageFile(''), DIRECTORY_SEPARATOR) . '-copy' . DIRECTORY_SEPARATOR . 'Helper.php';

        $exception = ForgedTrace::onto(new \RuntimeException('Request failed.'), [
            $this->frame($beside, null, 'strlen', ['harmless']),
        ]);

        TraceScrubber::scrub($exception);

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
            ['file' => self::APPLICATION_FILE, 'line' => 12, 'class' => Mfa::class, 'type' => '::', 'function' => 'verify'],
            ['file' => self::APPLICATION_FILE, 'line' => 14, 'class' => Mfa::class, 'type' => '::', 'function' => 'verify', 'args' => self::CODE],
        ];

        $exception = ForgedTrace::onto(new \RuntimeException('Verification failed.'), $frames);

        TraceScrubber::scrub($exception);

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
        $first  = ForgedTrace::onto(new \RuntimeException('First.'), [$this->frame(self::APPLICATION_FILE, Mfa::class, 'verify', [self::CODE])]);
        $second = ForgedTrace::onto(new \RuntimeException('Second.', 0, $first), [$this->frame(self::APPLICATION_FILE, Mfa::class, 'verify', [self::CODE])]);

        (new \ReflectionProperty(\Exception::class, 'previous'))->setValue($first, $second);

        TraceScrubber::scrub($second);

        self::assertSame(['[redacted]'], $this->arguments($first, 0));
        self::assertSame(['[redacted]'], $this->arguments($second, 0));
    }

    /**
     * Every previous exception in the chain is scrubbed too, an error
     * included.
     *
     * @return void
     */
    public function testScrubsEveryExceptionInTheChain(): void
    {
        $error = ForgedTrace::onto(new \Error('Decryption failed.'), [
            $this->frame(self::APPLICATION_FILE, Mfa::class, 'verify', [self::CODE]),
        ]);

        $exception = ForgedTrace::onto(new \RuntimeException('Verification failed.', 0, $error), [
            $this->frame(self::APPLICATION_FILE, Mfa::class, 'verify', [self::CODE]),
        ]);

        TraceScrubber::scrub($exception);

        self::assertSame(['[redacted]'], $this->arguments($exception, 0));
        self::assertSame(['[redacted]'], $this->arguments($error, 0));
    }

    /**
     * Scrubbing twice changes nothing more.
     *
     * @return void
     */
    public function testScrubbingIsIdempotent(): void
    {
        $exception = ForgedTrace::onto(new \RuntimeException('Verification failed.'), [
            $this->frame(self::APPLICATION_FILE, Mfa::class, 'verify', [self::CODE]),
        ]);

        TraceScrubber::scrub($exception);

        $once = $exception->getTrace();

        TraceScrubber::scrub($exception);

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
