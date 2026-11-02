<?php

declare(strict_types = 1);

namespace Tests\Unit\Verification;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Context\Caller;
use SineMacula\Laravel\Mfa\Context\PendingContext;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Verification\PurposeRule;
use Tests\Fixtures\Identities\NonEloquentIdentity;
use Tests\Fixtures\Requirements\SignInProofs;

/**
 * Unit tests for `PurposeRule`: a pending session is always completing its
 * sign-in, and an active one steps up unless it asks for a sign-in.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PurposeRule::class)]
final class PurposeRuleTest extends TestCase
{
    /**
     * What each caller asks for, and what it gets.
     *
     * @return iterable<string, array{0: bool, 1: ?\SineMacula\Laravel\Mfa\Enums\Purpose, 2: ?\SineMacula\Laravel\Mfa\Enums\Purpose}>
     */
    public static function purposes(): iterable
    {
        yield 'pending, nothing asked' => [true, null, Purpose::SIGN_IN];
        yield 'pending, a sign-in' => [true, Purpose::SIGN_IN, Purpose::SIGN_IN];
        yield 'pending, a step-up' => [true, Purpose::STEP_UP, null];
        yield 'pending, an enrolment' => [true, Purpose::ENROLLMENT, null];
        yield 'pending, a reauthentication' => [true, Purpose::REAUTHENTICATE, null];
        yield 'active, nothing asked' => [false, null, Purpose::STEP_UP];
        yield 'active, a step-up' => [false, Purpose::STEP_UP, Purpose::STEP_UP];
        yield 'active, a sign-in' => [false, Purpose::SIGN_IN, Purpose::SIGN_IN];
        yield 'active, an enrolment' => [false, Purpose::ENROLLMENT, null];
        yield 'active, a reauthentication' => [false, Purpose::REAUTHENTICATE, null];
    }

    /**
     * Each caller gets the purpose it may make the request for, or none.
     *
     * @param  bool  $pending
     * @param  ?\SineMacula\Laravel\Mfa\Enums\Purpose  $requested
     * @param  ?\SineMacula\Laravel\Mfa\Enums\Purpose  $expected
     * @return void
     */
    #[DataProvider('purposes')]
    public function testResolvesThePurpose(bool $pending, ?Purpose $requested, ?Purpose $expected): void
    {
        $identity = new NonEloquentIdentity;

        $context = $pending
            ? new PendingContext($identity, 'web', 'pending-1', SignInProofs::of($identity)->inSession('pending-1')->password(), Requirement::none(), [])
            : null;

        self::assertSame($expected, PurposeRule::resolve(new Caller($identity, $context), $requested));
    }
}
