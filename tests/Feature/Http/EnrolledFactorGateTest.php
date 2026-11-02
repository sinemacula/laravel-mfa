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
use Tests\Fixtures\Enrollment\Concerns\ArrangesEnrollment;
use Tests\Fixtures\Identities\FactorHolder;
use Tests\TestCase;

/**
 * What a confirmation promises holds at the gate: on an `enrolled` application
 * an active person's first factor, confirmed through a real enrolment, leaves
 * the session short, and under the default transition the next request through
 * `mfa` is refused until they verify with the new factor.
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

    /** @var string A route carrying the gate. */
    private const string GATED = 'gate/account';

    /** @var array<string, array<string, null>> The serialised form of asking for an additional verification at any age. */
    private const array VERIFIED = ['additional_verification' => ['max_age' => null]];

    /**
     * Arrange the application, which asks a verification of whoever has a
     * factor.
     *
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
     * The person passes with no factor, is gated once a first factor is
     * confirmed, and passes again on verifying with that factor.
     *
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
        self::assertTrue($this->mfa()->confirmEnrollment($this->grantOf($start), $this->appCode($start))->isConfirmed());

        $factor  = $this->pendingFactorOf($start);
        $refusal = $this->get(self::GATED)->exception;

        self::assertInstanceOf(InsufficientAuthenticationException::class, $refusal);
        self::assertSame(self::VERIFIED, $refusal->requirement->toArray());
        self::assertTrue($refusal->hasConfirmedFactor);
        self::assertCount(1, $refusal->offered);
        self::assertSame($factor->id, $refusal->offered[0]->id);

        Carbon::setTestNow(CarbonImmutable::now()->addSeconds(30));

        self::assertTrue(Mfa::verify(Submission::factor($factor->id, $this->appCode($start)))->isVerified());

        $this->get(self::GATED)->assertOk();
    }

    /**
     * A person whose only factor's stored status is none the package knows is
     * still held to MFA, by the trait's own rule, not read as having no factor
     * and let on: the gate refuses the request, and the route is never reached.
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
     * Define the route the test calls.
     *
     * @param  \Illuminate\Routing\Router  $router
     * @return void
     */
    #[\Override]
    protected function defineRoutes(mixed $router): void
    {
        $router->get(self::GATED, static fn (): string => 'reached')->middleware('mfa');
    }
}
