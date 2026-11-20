<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Context\SessionFirstFactor;
use SineMacula\Laravel\Mfa\Exceptions\InsufficientAuthenticationException;
use SineMacula\Laravel\Mfa\Http\Middleware\EnsureMfaRequirementIsMet;
use SineMacula\Laravel\Mfa\Requirements\ConfiguredFreshnessGate;
use SineMacula\Laravel\Mfa\Requirements\ProofRequirementCheck;
use SineMacula\Laravel\Mfa\Requirements\ReenrollmentObligation;
use SineMacula\Laravel\Mfa\Requirements\RequirementService;
use SineMacula\Laravel\Mfa\Requirements\StepUpRefusal;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use SineMacula\Laravel\Mfa\Verification\FactorOffers;
use SineMacula\Laravel\Mfa\Verification\Submission;
use Symfony\Component\HttpFoundation\Response;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Verification\Concerns\ArrangesVerification;

/**
 * The `mfa` middleware in `always` mode unless a test says otherwise, called
 * directly so the route and kernel are not measured.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EnsureMfaRequirementIsMet::class)]
#[CoversClass(RequirementService::class)]
#[CoversClass(ProofRequirementCheck::class)]
#[CoversClass(SessionFirstFactor::class)]
#[CoversClass(ReenrollmentObligation::class)]
#[CoversClass(ConfiguredFreshnessGate::class)]
#[CoversClass(StepUpRefusal::class)]
#[CoversClass(FactorOffers::class)]
final class RequirementGateQueryBudgetTest extends PerformanceContractTestCase
{
    use ArrangesVerification;

    /**
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeVerification();
        $this->enableApplication(['requirement' => 'always']);
    }

    /**
     * @return void
     */
    public function testAPassingRequestOnADeclaredFirstFactor(): void
    {
        $this->verified($this->signedInPerson());

        // Re-enrolment obligation (1); proofs, declaration and trust each read
        // the generation (3).
        self::assertSame(Response::HTTP_OK, $this->assertQueryBudget(4, 0, $this->gate(...))->getStatusCode());
    }

    /**
     * @return void
     */
    public function testAPassingRequestOnARecordedFirstFactor(): void
    {
        $user = $this->signedInPerson();

        $this->recordFirstFactor($user);
        $this->verified($user);

        // Re-enrolment obligation (1); proofs read the generation (1).
        self::assertSame(Response::HTTP_OK, $this->assertQueryBudget(2, 0, $this->gate(...))->getStatusCode());
    }

    /**
     * @return void
     */
    public function testAPassingRequestUnderEnrolledMode(): void
    {
        $this->enableApplication(['requirement' => 'enrolled']);
        $this->verified($this->signedInPerson());

        // Whether the identity is enrolled (1); then as in always mode (4).
        self::assertSame(Response::HTTP_OK, $this->assertQueryBudget(5, 0, $this->gate(...))->getStatusCode());
    }

    /**
     * @return void
     */
    public function testAPassingRequestOnAnOperationRoute(): void
    {
        $this->verified($this->signedInPerson());

        // As without the operation (4); freshness reads the proofs again (3).
        $response = $this->assertQueryBudget(7, 0, fn (): Response => $this->gate('operation=mfa.remove_factor'));

        self::assertSame(Response::HTTP_OK, $response->getStatusCode());
    }

    /**
     * @return void
     */
    public function testARefusedRequest(): void
    {
        $user = $this->signedInPerson();

        $this->recordFirstFactor($user);
        $this->totpFactor($user);
        $this->emailFactor($user);

        // Re-enrolment obligation (1); proofs (1); offers read the first factor
        // and the factors (2); whether any factor is confirmed (1).
        $refusal = $this->assertQueryBudget(5, 0, $this->refused(...));

        self::assertCount(2, $refusal->offered);
        self::assertTrue($refusal->hasConfirmedFactor);
    }

    /**
     * @return void
     */
    public function testAStaleSignInIsRefusedOnAnOperationRoute(): void
    {
        $user = $this->signedInPerson();

        $this->recordFirstFactor($user);
        $this->emailFactor($user);
        $this->verified($user);

        $this->travel(901)->seconds();

        self::assertSame(Response::HTTP_OK, $this->gate()->getStatusCode());

        // As a refusal without the operation (5); freshness reads the proofs
        // again (1).
        $refusal = $this->assertQueryBudget(6, 0, fn (): InsufficientAuthenticationException => $this->refused('operation=mfa.remove_factor'));

        self::assertSame(900, $refusal->maxAge());
        self::assertCount(2, $refusal->offered);
    }

    /**
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @return void
     */
    private function verified(TestUser $user): void
    {
        $factor = $this->totpFactor($user);

        self::assertTrue($this->mfa()->verify(Callers::current(), Submission::factor($factor->id, AuthenticatorApp::code($factor)))->isVerified());
    }

    /**
     * @param  string  ...$parameters
     * @return \Symfony\Component\HttpFoundation\Response
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\InsufficientAuthenticationException
     */
    private function gate(string ...$parameters): Response
    {
        return $this->container()->make(EnsureMfaRequirementIsMet::class)->handle(Request::create('/'), static fn (): Response => new Response, ...$parameters);
    }

    /**
     * @param  string  ...$parameters
     * @return \SineMacula\Laravel\Mfa\Exceptions\InsufficientAuthenticationException
     */
    private function refused(string ...$parameters): InsufficientAuthenticationException
    {
        try {
            $this->gate(...$parameters);
        } catch (InsufficientAuthenticationException $refusal) {
            return $refusal;
        }

        self::fail('The gate must refuse the request.');
    }
}
