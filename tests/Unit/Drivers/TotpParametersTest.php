<?php

declare(strict_types = 1);

namespace Tests\Unit\Drivers;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Drivers\TotpParameters;
use Tests\Fixtures\Factors\TotpStubFactor;

/**
 * Unit tests for `TotpParameters`: the RFC 6238 Appendix B test vectors for
 * each algorithm, the time step a moment falls in, the length of a new secret,
 * the bounds, and the parameters read from a factor.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TotpParameters::class)]
final class TotpParametersTest extends TestCase
{
    /** @var array<string, string> The RFC 6238 Appendix B key of each algorithm. */
    private const array KEYS = [
        'sha1'   => '12345678901234567890',
        'sha256' => '12345678901234567890123456789012',
        'sha512' => '1234567890123456789012345678901234567890123456789012345678901234',
    ];

    /**
     * Rows of `[algorithm, time, code]`: RFC 6238 Appendix B, 8 digits and a
     * 30-second period.
     *
     * @return iterable<string, array{string, int, string}>
     */
    public static function rfc6238Vectors(): iterable
    {
        $vectors = [
            59          => ['94287082', '46119246', '90693936'],
            1111111109  => ['07081804', '68084774', '25091201'],
            1111111111  => ['14050471', '67062674', '99943326'],
            1234567890  => ['89005924', '91819424', '93441116'],
            2000000000  => ['69279037', '90698825', '38618901'],
            20000000000 => ['65353130', '77737706', '47863826'],
        ];

        foreach ($vectors as $time => $codes) {
            foreach (TotpParameters::ALGORITHMS as $index => $algorithm) {
                yield sprintf('%s at %d', $algorithm, $time) => [$algorithm, $time, $codes[$index]];
            }
        }
    }

    /**
     * The code for the time step a moment falls in is the published one.
     *
     * @param  string  $algorithm
     * @param  int  $time
     * @param  string  $code
     * @return void
     */
    #[DataProvider('rfc6238Vectors')]
    public function testMatchesTheRfc6238Vector(string $algorithm, int $time, string $code): void
    {
        $parameters = new TotpParameters($algorithm, 8, 30);

        self::assertSame($code, $parameters->code(self::KEYS[$algorithm], $parameters->stepAt($time)));
    }

    /**
     * A shorter code is the low digits of the same value, zero-padded to its
     * length.
     *
     * @return void
     */
    public function testAShorterCodeKeepsItsLeadingZeros(): void
    {
        $sha1 = self::KEYS['sha1'];

        self::assertSame('081804', (new TotpParameters('sha1', 6, 30))->code($sha1, 37037036));
        self::assertSame('7081804', (new TotpParameters('sha1', 7, 30))->code($sha1, 37037036));
        self::assertSame('050219', (new TotpParameters('sha1', 6, 30))->code($sha1, 60000001));
    }

    /**
     * A moment falls in the step of whole periods since the epoch.
     *
     * @return void
     */
    public function testAMomentFallsInItsStep(): void
    {
        $parameters = new TotpParameters('sha1', 6, 30);

        self::assertSame(0, $parameters->stepAt(29));
        self::assertSame(1, $parameters->stepAt(30));
        self::assertSame(1, $parameters->stepAt(59));
        self::assertSame(2, (new TotpParameters('sha1', 6, 15))->stepAt(30));
    }

    /**
     * A new secret is as long as the algorithm's output, never under 160 bits.
     *
     * @return void
     */
    public function testANewSecretIsAsLongAsTheAlgorithmOutput(): void
    {
        self::assertSame(20, (new TotpParameters('sha1', 6, 30))->secretLength());
        self::assertSame(32, (new TotpParameters('sha256', 6, 30))->secretLength());
        self::assertSame(64, (new TotpParameters('sha512', 6, 30))->secretLength());
    }

    /**
     * Rows of `[algorithm, digits, period]` just outside the bounds.
     *
     * @return iterable<string, array{string, int, int}>
     */
    public static function outOfBounds(): iterable
    {
        yield 'an unknown algorithm' => ['md5', 6, 30];
        yield 'an upper case name' => ['SHA1', 6, 30];
        yield 'too few digits' => ['sha1', 5, 30];
        yield 'too many digits' => ['sha1', 9, 30];
        yield 'too short a period' => ['sha1', 6, 14];
        yield 'too long a period' => ['sha1', 6, 121];
    }

    /**
     * Parameters outside the bounds are refused, and none are read from a
     * factor that holds them.
     *
     * @param  string  $algorithm
     * @param  int  $digits
     * @param  int  $period
     * @return void
     */
    #[DataProvider('outOfBounds')]
    public function testRefusesParametersOutsideTheBounds(string $algorithm, int $digits, int $period): void
    {
        self::assertNull(TotpParameters::fromFactor(new TotpStubFactor('SECRET', $algorithm, $digits, $period)));

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('TOTP parameters must name one of sha1, sha256, sha512, 6 to 8 digits and a period of 15 to 120 seconds.');

        new TotpParameters($algorithm, $digits, $period);
    }

    /**
     * The bounds themselves are allowed.
     *
     * @return void
     */
    public function testAllowsTheBounds(): void
    {
        $least = new TotpParameters('sha1', 6, 15);
        $most  = new TotpParameters('sha512', 8, 120);

        self::assertSame(['sha1', 6, 15], [$least->algorithm, $least->digits, $least->period]);
        self::assertSame(['sha512', 8, 120], [$most->algorithm, $most->digits, $most->period]);
    }

    /**
     * A factor's parameters are read as it holds them, and none are read from a
     * factor missing any of them.
     *
     * @return void
     */
    public function testReadsTheParametersAFactorHolds(): void
    {
        $parameters = TotpParameters::fromFactor(new TotpStubFactor('SECRET', 'sha256', 7, 45));

        self::assertNotNull($parameters);
        self::assertSame(['sha256', 7, 45], [$parameters->algorithm, $parameters->digits, $parameters->period]);

        self::assertNull(TotpParameters::fromFactor(new TotpStubFactor('SECRET', null)));
        self::assertNull(TotpParameters::fromFactor(new TotpStubFactor('SECRET', 'sha1', null)));
        self::assertNull(TotpParameters::fromFactor(new TotpStubFactor('SECRET', 'sha1', 6, null)));
    }
}
