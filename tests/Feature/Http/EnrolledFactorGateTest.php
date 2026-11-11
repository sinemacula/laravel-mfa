<?php

declare(strict_types = 1);

namespace Tests\Feature\Http;

use Carbon\Carbon;
use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Contracts\SessionTransition;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentConfirmer;
use SineMacula\Laravel\Mfa\Exceptions\InsufficientAuthenticationException;
use SineMacula\Laravel\Mfa\Exceptions\InvalidModelException;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Http\Middleware\EnsureMfaRequirementIsMet;
use SineMacula\Laravel\Mfa\Http\MiddlewareSessionTransition;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Requirements\RequirementService;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use SineMacula\Laravel\Mfa\Verification\Submission;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Enrollment\Concerns\ArrangesEnrollment;
use Tests\Fixtures\Identities\FactorHolder;
use Tests\TestCase;

/**
 * On an `enrolled` application a confirmed first factor gates the session until
 * the person verifies with it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EnsureMfaRequirementIsMet::class)]
#[CoversClass(EnrollmentConfirmer::class)]
#[CoversClass(MiddlewareSessionTransition::class)]
final class EnrolledFactorGateTest extends TestCase
{
    use ArrangesEnrollment;

    /** @var string Route behind `mfa`. */
    private const string GATED = 'gate/account';

    /** @var array<string, array<string, null>> Additional verification at any age, serialised. */
    private const array VERIFIED = ['additional_verification' => ['max_age' => null]];

    /**
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeVerification();
        $this->enableApplication(['requirement' => 'enrolled']);
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testAConfirmedFirstFactorGatesThePersonUntilTheyVerifyWithIt(): void
    {
        $this->reauthenticatedPerson();

        $this->get(self::GATED)->assertOk();

        $start = $this->startedTotp();

        self::assertInstanceOf(MiddlewareSessionTransition::class, $this->container()->make(SessionTransition::class));
        self::assertTrue($this->mfa()->confirmEnrollment(Callers::current(), $this->grantOf($start), $this->appCode($start))->isConfirmed());

        $factor  = $this->pendingFactorOf($start);
        $refusal = $this->get(self::GATED)->exception;

        self::assertInstanceOf(InsufficientAuthenticationException::class, $refusal);
        self::assertSame(self::VERIFIED, $refusal->requirement->toArray());
        self::assertTrue($refusal->hasConfirmedFactor);
        self::assertCount(1, $refusal->offered);
        self::assertSame($factor->id, $refusal->offered[0]->id);

        Carbon::setTestNow(CarbonImmutable::now()->addSeconds(30));

        self::assertTrue(Mfa::verify(Callers::current(), Submission::factor($factor->id, $this->appCode($start)))->isVerified());

        $this->get(self::GATED)->assertOk();
    }

    /**
     * An unknown stored status still counts as a factor, so the request fails
     * rather than passing as factorless.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnUnknownStatusOnTheOnlyFactorStillGatesThePerson(): void
    {
        $holder = FactorHolder::query()->create(['email' => 'holder@example.test']);

        $this->actingAs($holder);
        $this->container()->make(ProofStore::class)->begin($holder, self::APPLICATION, self::SESSION);

        Factor::query()->create([
            ...AuthenticatorApp::FACTOR,
            'authenticatable_type' => $holder->getMorphClass(),
            'authenticatable_id'   => (string) $holder->id,
            'status'               => 'CONFIRMED',
            'application'          => self::APPLICATION,
        ]);

        self::assertTrue($holder->isMfaEnabled());
        self::assertSame(self::VERIFIED, $this->container()->make(RequirementService::class)->requirementFor($holder, self::APPLICATION)->toArray());

        $response = $this->get(self::GATED);

        $response->assertServerError();
        self::assertInstanceOf(InvalidModelException::class, $response->exception);
        self::assertStringContainsString('[status]', $response->exception->getMessage());
    }

    /**
     * @param  \Illuminate\Routing\Router  $router
     * @return void
     */
    #[\Override]
    protected function defineRoutes(mixed $router): void
    {
        $router->get(self::GATED, static fn (): string => 'reached')->middleware('mfa');
    }
}
