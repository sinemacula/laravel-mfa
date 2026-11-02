<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Enums\FactorStatus;
use SineMacula\Laravel\Mfa\Exceptions\InsufficientAuthenticationException;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use Symfony\Component\HttpKernel\Exception\HttpException;

/**
 * Unit tests for `InsufficientAuthenticationException`: what it carries, what
 * it adds no header for, and the data an RFC 9470 answer is built from.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(InsufficientAuthenticationException::class)]
final class InsufficientAuthenticationExceptionTest extends TestCase
{
    /** @var string What the exception says, in the shipped English. */
    private const string MESSAGE = 'Further authentication is required.';

    /**
     * It is a 401 with the shipped message in the default locale, and no
     * challenge header of its own: the package also serves cookie guards, so
     * the application chooses.
     *
     * @return void
     */
    public function testItIsAnUnauthorizedAnswerWithNoHeaderOfItsOwn(): void
    {
        $exception = new InsufficientAuthenticationException(Requirement::none());

        self::assertInstanceOf(HttpException::class, $exception);
        self::assertSame(401, $exception->getStatusCode());
        self::assertSame([], $exception->getHeaders());
        self::assertSame(self::MESSAGE, $exception->getMessage());
    }

    /**
     * By default it offers nothing, names no operation and reports no confirmed
     * factor.
     *
     * @return void
     */
    public function testItsDefaultsReportNothing(): void
    {
        $exception = new InsufficientAuthenticationException(Requirement::none());

        self::assertSame([], $exception->offered);
        self::assertNull($exception->operation);
        self::assertFalse($exception->hasConfirmedFactor);
    }

    /**
     * The requirements and the bound each gives.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Mfa\Requirements\Requirement, 1: ?int}>
     */
    public static function maximumAges(): iterable
    {
        yield 'nothing asked' => [Requirement::none(), null];
        yield 'an unbounded part' => [Requirement::none()->withAdditionalVerification(), null];
        yield 'one bounded part' => [Requirement::none()->withAdditionalVerification(300), 300];
        yield 'a bounded part after an unbounded one' => [Requirement::none()->withMultifactor()->withPhishingResistance(120), 120];
        yield 'the shorter of two' => [Requirement::none()->withAdditionalVerification(900)->withMinimumLevel(AssuranceLevel::AAL2, 60), 60];
        yield 'the shorter of two the other way' => [Requirement::none()->withAdditionalVerification(60)->withMinimumLevel(AssuranceLevel::AAL2, 900), 60];
    }

    /**
     * The maximum age is the shortest bound of any part; a part with no bound
     * sets none.
     *
     * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @param  ?int  $expected
     * @return void
     */
    #[DataProvider('maximumAges')]
    public function testTheMaximumAgeIsTheShortestBound(Requirement $requirement, ?int $expected): void
    {
        self::assertSame($expected, (new InsufficientAuthenticationException($requirement))->maxAge());
    }

    /**
     * The `acr` values are the minimum level's, or none.
     *
     * @return void
     */
    public function testTheAcrValuesAreTheMinimumLevels(): void
    {
        self::assertSame([], (new InsufficientAuthenticationException(Requirement::none()->withMultifactor()))->acrValues());
        self::assertSame(['aal2'], (new InsufficientAuthenticationException(Requirement::none()->withMinimumLevel(AssuranceLevel::AAL2)))->acrValues());
    }

    /**
     * The requirements and the header each gives.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Mfa\Requirements\Requirement, 1: string}>
     */
    public static function headers(): iterable
    {
        $base = 'Bearer error="insufficient_user_authentication", error_description="' . self::MESSAGE . '"';

        yield 'neither' => [Requirement::none()->withMultifactor(), $base];
        yield 'a level' => [Requirement::none()->withMinimumLevel(AssuranceLevel::AAL2), $base . ', acr_values="aal2"'];
        yield 'an age' => [Requirement::none()->withAdditionalVerification(300), $base . ', max_age="300"'];
        yield 'both' => [Requirement::none()->withMinimumLevel(AssuranceLevel::AAL2, 300), $base . ', acr_values="aal2", max_age="300"'];
    }

    /**
     * The header states what is present and omits what is absent.
     *
     * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @param  string  $expected
     * @return void
     */
    #[DataProvider('headers')]
    public function testTheHeaderStatesOnlyWhatIsPresent(Requirement $requirement, string $expected): void
    {
        self::assertSame($expected, (new InsufficientAuthenticationException($requirement))->wwwAuthenticate());
    }

    /**
     * The scheme may be chosen by the application.
     *
     * @return void
     */
    public function testTheSchemeIsTheCallers(): void
    {
        $header = (new InsufficientAuthenticationException(Requirement::none()))->wwwAuthenticate('DPoP');

        self::assertSame('DPoP error="insufficient_user_authentication", error_description="' . self::MESSAGE . '"', $header);
    }

    /**
     * The array form is pinned exactly, its factors masked.
     *
     * @return void
     */
    public function testTheArrayIsPinnedAndItsDestinationsMasked(): void
    {
        $summary = new FactorSummary('factor-1', 'email', 'Work', 'pe****@example.test', FactorStatus::CONFIRMED, true, null);

        $exception = new InsufficientAuthenticationException(
            Requirement::none()->withMinimumLevel(AssuranceLevel::AAL2)->withAdditionalVerification(300),
            [$summary],
            'billing.close',
            true,
        );

        self::assertSame([
            'error'                => 'insufficient_user_authentication',
            'max_age'              => 300,
            'acr_values'           => ['aal2'],
            'requirement'          => ['additional_verification' => ['max_age' => 300], 'minimum_level' => ['level' => 'aal2', 'max_age' => null]],
            'operation'            => 'billing.close',
            'has_confirmed_factor' => true,
            'factors'              => [[
                'id'                 => 'factor-1',
                'type'               => 'email',
                'label'              => 'Work',
                'masked_destination' => 'pe****@example.test',
                'status'             => 'confirmed',
                'preferred'          => true,
                'last_used_at'       => null,
                'disabled'           => false,
            ]],
        ], $exception->toArray());
    }
}
