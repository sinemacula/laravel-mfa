<?php

declare(strict_types = 1);

namespace Tests\Feature\Journeys;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Exceptions\InsufficientAuthenticationException;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Http\Middleware\EnsureMfaRequirementIsMet;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofStoreCompletion;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Verification\Submission;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Enrollment\Concerns\ArrangesEnrollment;
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;

/**
 * What a pending sign-in proves through the default completion is what the gate
 * counts once the authentication layer activates the session.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ProofStoreCompletion::class)]
#[CoversClass(EnsureMfaRequirementIsMet::class)]
final class PendingSignInJourneyTest extends TestCase
{
    use ArrangesEnrollment;

    /** @var string Route behind `mfa`. */
    private const string GATED = 'gate/account';

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
     *
     * @throws \Throwable
     */
    public function testAVerifiedPendingSignInPassesTheGateOnceActive(): void
    {
        $user = $this->person();

        $this->beginSignIn($user, self::PENDING);
        $this->pendingSession($user, Requirement::none()->withAdditionalVerification());

        $factor = $this->emailFactor($user);

        self::assertSame([$factor->id], array_column(Mfa::offeredFactors(Callers::current()), 'id'));
        self::assertInstanceOf(InsufficientAuthenticationException::class, $this->get(self::GATED)->exception);

        [$challenge, $code] = $this->sentCode($factor, Purpose::SIGN_IN);

        self::assertTrue(Mfa::verify(Callers::current(), Submission::challenge($factor->id, $challenge, $code))->isVerified());

        $this->activate($user);

        $this->get(self::GATED)->assertOk();
        self::assertSame([Purpose::SIGN_IN], $this->purposes());
    }

    /**
     * No verification follows the enrolment.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABootstrapEnrollmentPassesTheGateOnceActive(): void
    {
        $user = $this->bootstrapPerson(Requirement::none()->withAdditionalVerification(), [PendingAction::LIST_FACTORS, ...self::BOOTSTRAP_ACTIONS]);

        config()->set('mfa.applications.' . self::APPLICATION . '.requirement', 'always');

        $refusal = $this->get(self::GATED)->exception;

        self::assertInstanceOf(InsufficientAuthenticationException::class, $refusal);
        self::assertFalse($refusal->hasConfirmedFactor);
        self::assertSame([], $refusal->offered);

        $start        = $this->startedTotp();
        $confirmation = Mfa::confirmEnrollment(Callers::current(), $this->grantOf($start), $this->appCode($start));

        self::assertTrue($confirmation->isConfirmed());
        self::assertTrue($confirmation->verification?->isVerified());

        $this->activate($user);

        $this->get(self::GATED)->assertOk();
        self::assertSame([Purpose::ENROLLMENT], $this->purposes());
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

    /**
     * As the authentication layer does: the pending session goes and the guard
     * holds its identity, under the same sign-in.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function activate(TestUser $user): void
    {
        $this->noPendingSession();
        $this->actingAs($user);

        self::assertSame(self::PENDING, $this->container()->make(ProofStore::class)->currentSession($user, self::APPLICATION));
    }

    /**
     * @return list<\SineMacula\Laravel\Mfa\Enums\Purpose>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function purposes(): array
    {
        return array_map(static fn (Proof $proof): Purpose => $proof->binding->purpose, Mfa::proofs(Callers::current()));
    }
}
