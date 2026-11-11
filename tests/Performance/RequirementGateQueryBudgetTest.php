<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Context\SessionFirstFactor;
use SineMacula\Laravel\Mfa\Http\Middleware\EnsureMfaRequirementIsMet;
use SineMacula\Laravel\Mfa\Requirements\ProofRequirementCheck;
use SineMacula\Laravel\Mfa\Requirements\ReenrollmentObligation;
use SineMacula\Laravel\Mfa\Requirements\RequirementService;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use SineMacula\Laravel\Mfa\Verification\Submission;
use Symfony\Component\HttpFoundation\Response;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Verification\Concerns\ArrangesVerification;

/**
 * The `mfa` middleware passing a request in `always` mode, called directly so
 * the route and kernel are not measured.
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
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @return void
     */
    private function verified(TestUser $user): void
    {
        $factor = $this->totpFactor($user);

        self::assertTrue($this->mfa()->verify(Callers::current(), Submission::factor($factor->id, AuthenticatorApp::code($factor)))->isVerified());
    }

    /**
     * @return \Symfony\Component\HttpFoundation\Response
     */
    private function gate(): Response
    {
        return $this->container()->make(EnsureMfaRequirementIsMet::class)->handle(Request::create('/'), static fn (): Response => new Response);
    }
}
