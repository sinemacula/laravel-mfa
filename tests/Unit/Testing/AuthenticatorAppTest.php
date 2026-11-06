<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing;

use Carbon\Carbon;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use SineMacula\Laravel\Mfa\Verification\Submission;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Verification\Concerns\ArrangesVerification;
use Tests\TestCase;

/**
 * The authenticator app a test stands in for: the published vectors at a frozen
 * time, the real driver accepting what it shows, and the refusal of a factor it
 * cannot read, which never shows the factor's secret.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthenticatorApp::class)]
final class AuthenticatorAppTest extends TestCase
{
    use ArrangesVerification;

    /**
     * Arrange the verification the real driver is tested through.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeVerification();
    }

    /**
     * Release the frozen clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();

        parent::tearDown();
    }

    /**
     * The codes of RFC 6238 Appendix B and RFC 4226 Appendix D for the shipped
     * key, by the time and the steps away from it, written out here so they
     * hold independently of the code being tested. The 8-digit values are the
     * RFC's; their last six digits are the same counter's 6-digit code.
     *
     * @return iterable<string, array{0: int, 1: int, 2: string}>
     */
    public static function vectors(): iterable
    {
        yield 'the RFC 6238 time 59' => [59, 0, '287082'];
        yield 'the RFC 6238 time 1111111109' => [1111111109, 0, '081804'];
        yield 'the RFC 6238 time 2000000000' => [2000000000, 0, '279037'];
        yield 'the step before counter 1, which is counter 0' => [59, -1, '755224'];
        yield 'the step after counter 1, which is counter 2' => [59, 1, '359152'];
    }

    /**
     * The code shown at a frozen time is the published one, and steps move it
     * by the factor's period.
     *
     * @param  int  $time
     * @param  int  $steps
     * @param  string  $code
     * @return void
     */
    #[DataProvider('vectors')]
    public function testTheCodeIsThePublishedOneAtAFrozenTime(int $time, int $steps, string $code): void
    {
        Carbon::setTestNow(Carbon::createFromTimestampUTC($time));

        self::assertSame($code, AuthenticatorApp::code(new Factor(AuthenticatorApp::FACTOR), $steps));
    }

    /**
     * The factor's own parameters are read: eight digits give the RFC's eight
     * digits, and a longer period gives another step.
     *
     * @return void
     */
    public function testTheFactorsOwnParametersAreRead(): void
    {
        Carbon::setTestNow(Carbon::createFromTimestampUTC(59));

        self::assertSame('94287082', AuthenticatorApp::code(new Factor([...AuthenticatorApp::FACTOR, 'totp_digits' => 8])));
        self::assertSame('755224', AuthenticatorApp::code(new Factor([...AuthenticatorApp::FACTOR, 'totp_period' => 60])));
    }

    /**
     * The real driver accepts the code at a frozen time, and accepts it once:
     * the same code replays, so a test moves the clock or passes steps for
     * another.
     *
     * @return void
     */
    public function testTheRealDriverAcceptsTheCodeOnce(): void
    {
        $user = $this->signedInPerson();

        $this->recordFirstFactor($user);

        $factor = $this->totpFactor($user);
        $code   = AuthenticatorApp::code($factor);

        self::assertTrue(Mfa::verify(Callers::current(), Submission::factor($factor->id, $code))->isVerified());
        self::assertFalse(Mfa::verify(Callers::current(), Submission::factor($factor->id, $code))->isVerified());

        Carbon::setTestNow(Carbon::now()->addSeconds(120));

        self::assertTrue(Mfa::verify(Callers::current(), Submission::factor($factor->id, AuthenticatorApp::code($factor->refresh())))->isVerified());
    }

    /**
     * What no code can be made for, none of whose refusals show the secret.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: string}>
     */
    public static function unreadableFactors(): iterable
    {
        yield 'a factor of another type with plausible parameters' => [['type' => 'email'], 'not a TOTP factor'];
        yield 'no parameters' => [['totp_algorithm' => null, 'totp_digits' => null, 'totp_period' => null], 'no valid TOTP parameters'];
        yield 'invalid digits' => [['totp_digits' => 5], 'no valid TOTP parameters'];
        yield 'an invalid algorithm' => [['totp_algorithm' => 'md5'], 'no valid TOTP parameters'];
        yield 'no secret' => [['secret' => null], 'no usable Base32 secret'];
        yield 'an empty secret' => [['secret' => ''], 'no usable Base32 secret'];
        yield 'a secret too short to decode to a byte' => [['secret' => 'G'], 'no usable Base32 secret'];
        yield 'a secret that is not Base32' => [['secret' => 'not-base32-1890'], 'no usable Base32 secret'];
    }

    /**
     * A factor no code can be made for is refused, saying why, without its
     * secret.
     *
     * @param  array<string, mixed>  $attributes
     * @param  string  $reason
     * @return void
     */
    #[DataProvider('unreadableFactors')]
    public function testAFactorNoCodeCanBeMadeForIsRefused(array $attributes, string $reason): void
    {
        $factor = new Factor([...AuthenticatorApp::FACTOR, ...$attributes]);

        try {
            AuthenticatorApp::code($factor);
        } catch (\InvalidArgumentException $exception) {
            self::assertStringContainsString($reason, $exception->getMessage());
            self::assertStringNotContainsString(AuthenticatorApp::SECRET, $exception->getMessage());

            $secret = $factor->getSecret();

            if ($secret !== null && $secret !== '') {
                self::assertStringNotContainsString($secret, $exception->getMessage());
            }

            return;
        }

        self::fail('The factor must be refused.');
    }
}
