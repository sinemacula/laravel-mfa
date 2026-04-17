<?php

declare(strict_types = 1);

namespace Tests\Unit\Middleware;

use Illuminate\Container\Container;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Facade;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Exceptions\MfaExpiredException;
use SineMacula\Laravel\Mfa\Exceptions\MfaRequiredException;
use SineMacula\Laravel\Mfa\Middleware\RequireMfa;
use SineMacula\Laravel\Mfa\Support\FactorSummary;
use Tests\Fixtures\FakeMfaManager;

/**
 * Unit tests for the `RequireMfa` middleware.
 *
 * Uses a test double of the MFA manager bound against the `'mfa'` facade
 * accessor so we can exercise every branch without touching the database or the
 * full service provider stack.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class RequireMfaTest extends TestCase
{
    /** @var \Illuminate\Container\Container */
    private Container $container;

    /**
     * Set up the test fixtures.
     *
     * @return void
     */
    protected function setUp(): void
    {
        parent::setUp();

        $this->container = new Container;
        Container::setInstance($this->container);
        Facade::setFacadeApplication($this->container);
        Facade::clearResolvedInstances();
    }

    /**
     * Tear down the test fixtures.
     *
     * @return void
     */
    protected function tearDown(): void
    {
        Facade::clearResolvedInstances();
        // Tear-down accepts null even though the upstream stub claims
        // non-null is required.
        // @phpstan-ignore argument.type
        Facade::setFacadeApplication(null);
        Container::setInstance(null);

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
        $factor->method('getDriver')->willReturn('email');
        $factor->method('getLabel')->willReturn(null);
        $factor->method('getRecipient')->willReturn('user@example.com');
        $factor->method('getVerifiedAt')->willReturn(null);

        $manager            = new FakeMfaManager;
        $manager->shouldUse = true;
        $manager->isSetup   = false;
        // The fake's `$factors` is typed Collection<int, Factor>; the
        // test injects a Collection of MockObject Factor doubles that
        // satisfy the interface but not PHPStan's strict-class check.
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
     * Test throws mfa required when never verified.
     *
     * @return void
     */
    public function testThrowsMfaRequiredWhenNeverVerified(): void
    {
        $manager                  = new FakeMfaManager;
        $manager->shouldUse       = true;
        $manager->isSetup         = true;
        $manager->hasEverVerified = false;
        $manager->factors         = null;
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
     * Test throws mfa expired when verification expired.
     *
     * @return void
     */
    public function testThrowsMfaExpiredWhenVerificationExpired(): void
    {
        $factor = self::createStub(Factor::class);
        $factor->method('getFactorIdentifier')->willReturn('id-2');
        $factor->method('getDriver')->willReturn('totp');
        $factor->method('getLabel')->willReturn('Authenticator');
        $factor->method('getRecipient')->willReturn(null);
        $factor->method('getVerifiedAt')->willReturn(null);

        $manager                  = new FakeMfaManager;
        $manager->shouldUse       = true;
        $manager->isSetup         = true;
        $manager->hasEverVerified = true;
        $manager->hasExpired      = true;
        // The fake's `$factors` is typed Collection<int, Factor>; the
        // test injects a Collection of MockObject Factor doubles that
        // satisfy the interface but not PHPStan's strict-class check.
        // @phpstan-ignore assign.propertyType
        $manager->factors = new Collection([$factor]);
        $this->bindManager($manager);

        $middleware = new RequireMfa;
        $request    = Request::create('/');

        try {
            $middleware->handle($request, static fn (): Response => new Response('ok'));
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
        $manager                  = new FakeMfaManager;
        $manager->shouldUse       = true;
        $manager->isSetup         = true;
        $manager->hasEverVerified = true;
        $manager->hasExpired      = false;
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
     * Bind the supplied fake manager against the container's `'mfa'` key.
     *
     * @param  \Tests\Fixtures\FakeMfaManager  $manager
     * @return void
     */
    private function bindManager(FakeMfaManager $manager): void
    {
        $this->container->instance('mfa', $manager);
    }
}
