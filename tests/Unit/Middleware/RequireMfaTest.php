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
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Middleware\RequireMfa;
use SineMacula\Laravel\Mfa\Support\FactorSummary;

/**
 * Unit tests for the `RequireMfa` middleware.
 *
 * Uses a test double of the MFA manager bound against the `'mfa'` facade
 * accessor so we can exercise every branch without touching the database
 * or the full service provider stack.
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
        Facade::setFacadeApplication(null); // @phpstan-ignore argument.type
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

        $result = $middleware->handle($request, static fn (): Response => $response);

        self::assertSame($response, $result);
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

        $result = $middleware->handle($request, static fn (): Response => $response);

        self::assertSame($response, $result);
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
        $result  = $middleware->handle($request, static function (Request $passed) use ($request, &$invoked, $response): Response {
            $invoked = $passed === $request;

            return $response;
        });

        self::assertTrue($invoked);
        self::assertSame($response, $result);
    }

    /**
     * Bind the supplied fake manager against the container's `'mfa'` key.
     *
     * @param  \Tests\Unit\Middleware\FakeMfaManager  $manager
     * @return void
     */
    private function bindManager(FakeMfaManager $manager): void
    {
        $this->container->instance('mfa', $manager);
    }
}

/**
 * Test double for `MfaManager` used by the `RequireMfa` middleware tests.
 *
 * Extends the real manager so the facade's `@method` assertions line up,
 * but bypasses the container-backed Manager constructor — we only poke
 * the handful of methods the middleware actually invokes.
 *
 * @internal
 */
final class FakeMfaManager extends MfaManager // @phpstan-ignore-line
{
    public bool $shouldUse       = true;
    public bool $isSetup         = true;
    public bool $hasEverVerified = true;
    public bool $hasExpired      = false;

    /** @var ?\Illuminate\Support\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\Factor> */
    public ?Collection $factors = null;

    /**
     * Intentionally skip parent::__construct to avoid requiring a full
     * container; the middleware only calls the overrides below.
     *
     * @phpstan-ignore constructor.missingParentCall
     */
    public function __construct() {}

    /**
     * Should use.
     *
     * @return bool
     */
    public function shouldUse(): bool
    {
        return $this->shouldUse;
    }

    /**
     * Is setup.
     *
     * @return bool
     */
    public function isSetup(): bool
    {
        return $this->isSetup;
    }

    /**
     * Has ever verified.
     *
     * @return bool
     */
    public function hasEverVerified(): bool
    {
        return $this->hasEverVerified;
    }

    /**
     * Has expired.
     *
     * @param  ?int  $expiresAfter
     * @return bool
     */
    public function hasExpired(?int $expiresAfter = null): bool
    {
        return $this->hasExpired;
    }

    /**
     * Get factors.
     *
     * @return ?Collection
     */
    public function getFactors(): ?Collection
    {
        return $this->factors;
    }
}
