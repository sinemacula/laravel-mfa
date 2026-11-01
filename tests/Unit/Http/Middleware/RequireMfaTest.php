<?php

declare(strict_types = 1);

namespace Tests\Unit\Http\Middleware;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Container\Container;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Facade;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Assurance\Channel;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\FactorStatus;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Exceptions\MfaExpiredException;
use SineMacula\Laravel\Mfa\Exceptions\MfaRequiredException;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use SineMacula\Laravel\Mfa\Http\Middleware\RequireMfa;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use Tests\Fixtures\Http\FakeMfaManager;
use Tests\Unit\Concerns\BuildsProofs;

/**
 * Unit tests for the `RequireMfa` middleware.
 *
 * Uses a test double of the MFA manager bound against the `'mfa'` facade
 * accessor, seeded with the proofs of the current sign-in, so we can exercise
 * every branch without touching the database or the full service provider
 * stack. The clock is frozen, so every proof's age is exact.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RequireMfa::class)]
final class RequireMfaTest extends TestCase
{
    use BuildsProofs;

    /** @var \Illuminate\Container\Container */
    private Container $container;

    /**
     * Set up the test fixtures.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->container = new Container;
        Container::setInstance($this->container);
        Facade::setFacadeApplication($this->container);
        Facade::clearResolvedInstances();

        $this->container->instance(Repository::class, new ConfigRepository);

        CarbonImmutable::setTestNow('2026-11-01T10:00:00.000000+00:00');
    }

    /**
     * Tear down the test fixtures.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Facade::clearResolvedInstances();
        // Tear-down accepts null even though the upstream stub claims non-null
        // is required.
        // @phpstan-ignore argument.type
        Facade::setFacadeApplication(null);
        Container::setInstance(null);
        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * Test passes through when skip mfa attribute set.
     *
     * @return void
     */
    public function testPassesThroughWhenSkipMfaAttributeSet(): void
    {
        $this->bindManager(new FakeMfaManager);

        $middleware = new RequireMfa;
        $request    = Request::create('/');
        $request->attributes->set('skip_mfa', true);
        $response = new Response('ok');

        $handled = $middleware->handle($request, static fn (): Response => $response);

        self::assertSame($response, $handled);
    }

    /**
     * Test passes through when should use returns false.
     *
     * @return void
     */
    public function testPassesThroughWhenShouldUseReturnsFalse(): void
    {
        $manager            = new FakeMfaManager;
        $manager->shouldUse = false;
        $this->bindManager($manager);

        $middleware = new RequireMfa;
        $request    = Request::create('/');
        $response   = new Response('ok');

        $handled = $middleware->handle($request, static fn (): Response => $response);

        self::assertSame($response, $handled);
    }

    /**
     * Test throws mfa required when not setup.
     *
     * @return void
     */
    public function testThrowsMfaRequiredWhenNotSetup(): void
    {
        $factor = self::createStub(Factor::class);
        $factor->method('getFactorIdentifier')->willReturn('id-1');
        $factor->method('getType')->willReturn('email');
        $factor->method('getLabel')->willReturn(null);
        $factor->method('getDestination')->willReturn('user@example.com');
        $factor->method('getStatus')->willReturn(FactorStatus::CONFIRMED);
        $factor->method('getLastUsedAt')->willReturn(null);

        $manager            = new FakeMfaManager;
        $manager->shouldUse = true;
        $manager->isSetup   = false;
        // The fake's `$factors` is typed Collection<int, Factor>; the test
        // injects a Collection of MockObject Factor doubles that satisfy the
        // interface but not PHPStan's strict-class check.
        // @phpstan-ignore assign.propertyType
        $manager->factors = new Collection([$factor]);
        $this->bindManager($manager);

        $middleware = new RequireMfa;
        $request    = Request::create('/');

        try {
            $middleware->handle($request, static fn (): Response => new Response('ok'));
            self::fail('Expected MfaRequiredException to be thrown.');
        } catch (MfaRequiredException $exception) {
            $summaries = $exception->getFactors();
            self::assertCount(1, $summaries);
            self::assertInstanceOf(FactorSummary::class, $summaries[0]);
            self::assertSame('id-1', $summaries[0]->id);
        }
    }

    /**
     * Test throws mfa required when the sign-in holds no proof.
     *
     * @return void
     */
    public function testThrowsMfaRequiredWhenNeverVerified(): void
    {
        $manager            = new FakeMfaManager;
        $manager->shouldUse = true;
        $manager->isSetup   = true;
        $manager->factors   = null;
        $this->bindManager($manager);

        $middleware = new RequireMfa;
        $request    = Request::create('/');

        try {
            $middleware->handle($request, static fn (): Response => new Response('ok'));
            self::fail('Expected MfaRequiredException to be thrown.');
        } catch (MfaRequiredException $exception) {
            self::assertSame([], $exception->getFactors());
        }
    }

    /**
     * Test throws mfa expired when the newest verification is past the window.
     *
     * @return void
     */
    public function testThrowsMfaExpiredWhenVerificationExpired(): void
    {
        $factor = self::createStub(Factor::class);
        $factor->method('getFactorIdentifier')->willReturn('id-2');
        $factor->method('getType')->willReturn('totp');
        $factor->method('getLabel')->willReturn('Authenticator');
        $factor->method('getDestination')->willReturn(null);
        $factor->method('getStatus')->willReturn(FactorStatus::CONFIRMED);
        $factor->method('getLastUsedAt')->willReturn(null);

        $manager            = new FakeMfaManager;
        $manager->shouldUse = true;
        $manager->isSetup   = true;
        $manager->proofs    = [self::verifiedMinutesAgo(61)];
        // The fake's `$factors` is typed Collection<int, Factor>; the test
        // injects a Collection of MockObject Factor doubles that satisfy the
        // interface but not PHPStan's strict-class check.
        // @phpstan-ignore assign.propertyType
        $manager->factors = new Collection([$factor]);
        $this->bindManager($manager);

        $middleware = new RequireMfa;
        $request    = Request::create('/');

        try {
            $middleware->handle($request, static fn (): Response => new Response('ok'), '60');
            self::fail('Expected MfaExpiredException to be thrown.');
        } catch (MfaExpiredException $exception) {
            $summaries = $exception->getFactors();
            self::assertCount(1, $summaries);
            self::assertInstanceOf(FactorSummary::class, $summaries[0]);
            self::assertSame('id-2', $summaries[0]->id);
        }
    }

    /**
     * Test calls next and returns response on success.
     *
     * @return void
     */
    public function testCallsNextAndReturnsResponseOnSuccess(): void
    {
        $manager            = new FakeMfaManager;
        $manager->shouldUse = true;
        $manager->isSetup   = true;
        $manager->proofs    = [self::verifiedMinutesAgo(1)];
        $this->bindManager($manager);

        $middleware = new RequireMfa;
        $request    = Request::create('/');
        $response   = new Response('allowed');

        $invoked = false;
        $handled = $middleware->handle($request, static function (Request $passed) use ($request, &$invoked, $response): Response {
            $invoked = $passed === $request;

            return $response;
        });

        self::assertTrue($invoked);
        self::assertSame($response, $handled);
    }

    /**
     * A first factor alone is no verification.
     *
     * @return void
     */
    public function testAFirstFactorAloneIsNoVerification(): void
    {
        $this->expectException(MfaRequiredException::class);

        $this->runWith([self::proof([
            'kind'      => ProofKind::FIRST_FACTOR,
            'method'    => 'password',
            'channel'   => new Channel(ChannelKind::PASSWORD),
            'reference' => null,
            'provedAt'  => CarbonImmutable::now()->subMinute(),
            'binding'   => new ProofBinding('user', '42', 'web', 'sign-in-1', Purpose::SIGN_IN),
        ])], '60');
    }

    /**
     * A recovery code proof is a verification.
     *
     * @return void
     */
    public function testARecoveryCodeIsAVerification(): void
    {
        self::assertTrue($this->runWith([self::proof([
            'kind'      => ProofKind::RECOVERY_CODE,
            'method'    => 'backup_code',
            'channel'   => null,
            'reference' => null,
            'provedAt'  => CarbonImmutable::now()->subMinute(),
        ])], '60'));
    }

    /**
     * The proofs, the route's window and whether the request passes: the
     * newest verification is judged, whatever order the proofs come in, and
     * one exactly at the window's edge still passes.
     *
     * @return iterable<string, array{0: list<int>, 1: string, 2: bool}>
     */
    public static function windows(): iterable
    {
        yield 'within the window' => [[4], '5', true];
        yield 'at the edge of the window' => [[60], '60', true];
        yield 'a minute past the window' => [[61], '60', false];
        yield 'the newest of several, oldest first' => [[120, 1], '5', true];
        yield 'the newest of several, newest first' => [[1, 120], '5', true];
        yield 'a window of zero' => [[0], '0', false];
        yield 'a verification in the future' => [[-1], '60', false];
    }

    /**
     * The newest verification passes within the route's window and is
     * expired past it, at a window of zero, or when dated in the future.
     *
     * @param  list<int>  $minutesAgo
     * @param  string  $window
     * @param  bool  $passes
     * @return void
     */
    #[DataProvider('windows')]
    public function testJudgesTheNewestVerificationAgainstTheWindow(array $minutesAgo, string $window, bool $passes): void
    {
        if (!$passes) {
            $this->expectException(MfaExpiredException::class);
        }

        self::assertTrue($this->runWith(array_map(self::verifiedMinutesAgo(...), $minutesAgo), $window));
    }

    /**
     * Without a route window, `mfa.proofs.max_age_minutes` is the window.
     *
     * @return void
     */
    public function testUsesTheConfiguredWindowWithoutARouteWindow(): void
    {
        $this->container->instance(Repository::class, new ConfigRepository(['mfa' => ['proofs' => ['max_age_minutes' => 30]]]));

        self::assertTrue($this->runWith([self::verifiedMinutesAgo(30)], null));

        $this->expectException(MfaExpiredException::class);

        $this->runWith([self::verifiedMinutesAgo(31)], null);
    }

    /**
     * Run the middleware for a set-up identity whose sign-in holds the given
     * proofs, reporting whether the request reached the next handler.
     *
     * @param  list<\SineMacula\Laravel\Mfa\Proofs\Proof>  $proofs
     * @param  ?string  $window
     * @return bool
     */
    private function runWith(array $proofs, ?string $window): bool
    {
        $manager         = new FakeMfaManager;
        $manager->proofs = $proofs;
        $this->bindManager($manager);

        $reached = false;

        (new RequireMfa)->handle(Request::create('/'), static function () use (&$reached): Response {
            $reached = true;

            return new Response('ok');
        }, $window);

        return $reached;
    }

    /**
     * An additional factor proof made the given number of minutes ago.
     *
     * @param  int  $minutes
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     */
    private static function verifiedMinutesAgo(int $minutes): Proof
    {
        return self::proof(['provedAt' => CarbonImmutable::now()->subMinutes($minutes)]);
    }

    /**
     * Bind the supplied fake manager against the container's `'mfa'` key.
     *
     * @param  \Tests\Fixtures\Http\FakeMfaManager  $manager
     * @return void
     */
    private function bindManager(FakeMfaManager $manager): void
    {
        $this->container->instance('mfa', $manager);
    }
}
