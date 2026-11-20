<?php

declare(strict_types = 1);

namespace Tests\Feature\Journeys;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Auth;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Contracts\Reauthenticator;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Exceptions\InsufficientAuthenticationException;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Http\Middleware\EnsureMfaRequirementIsMet;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use SineMacula\Laravel\Mfa\Verification\FactorOffers;
use SineMacula\Laravel\Mfa\Verification\Submission;
use SineMacula\Laravel\Mfa\Verification\VerificationService;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Enrollment\Concerns\ArrangesEnrollment;
use Tests\Fixtures\Seams\FreshReauthenticator;
use Tests\TestCase;

/**
 * A factor belongs to the person: enrolled through one application, it is
 * offered, verified and locked in another, while each keeps its own proofs.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EnsureMfaRequirementIsMet::class)]
#[CoversClass(FactorOffers::class)]
#[CoversClass(VerificationService::class)]
final class MultiApplicationJourneyTest extends TestCase
{
    use ArrangesEnrollment;

    /** @var string */
    private const string ADMIN = 'admin';

    /** @var string Route behind `mfa` on `web`. */
    private const string WEB_GATED = 'web/account';

    /** @var string Route behind `mfa` on `admin`. */
    private const string ADMIN_GATED = 'admin/account';

    /**
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeVerification();

        $password = ['method' => 'password', 'channel' => 'password'];

        config()->set('auth.guards.' . self::ADMIN, ['driver' => 'session', 'provider' => 'users']);
        config()->set('mfa.applications.' . self::APPLICATION, ['types' => ['totp'], 'requirement' => 'enrolled', 'first_factor' => $password]);
        config()->set('mfa.applications.' . self::ADMIN, ['types' => ['totp'], 'requirement' => 'always', 'first_factor' => $password]);
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFactorEnrolledThroughWebIsOfferedAndVerifiedInAdmin(): void
    {
        $factor = $this->enrolledThroughWeb();

        $refusal = $this->get(self::ADMIN_GATED)->exception;

        self::assertInstanceOf(InsufficientAuthenticationException::class, $refusal);
        self::assertSame([$factor->id], array_column($refusal->offered, 'id'));

        CarbonImmutable::setTestNow(CarbonImmutable::now()->addSeconds(30));

        self::assertTrue(Mfa::verify(Callers::current(self::ADMIN), Submission::factor($factor->id, AuthenticatorApp::code($factor)))->isVerified());

        $this->get(self::ADMIN_GATED)->assertOk();

        self::assertSame([], Mfa::proofs(Callers::current(self::APPLICATION)));
        self::assertInstanceOf(InsufficientAuthenticationException::class, $this->get(self::WEB_GATED)->exception);
        self::assertSame(FailureReason::NOT_FOUND, Mfa::removeFactor(Callers::current(self::ADMIN), $factor->id)->reason);
        self::assertTrue(Factor::query()->whereKey($factor->id)->exists());
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testFailuresThroughWebLockTheFactorInAdmin(): void
    {
        $factor = $this->enrolledThroughWeb();
        $wrong  = AuthenticatorApp::code($factor, 5);

        for ($attempt = 0; $attempt < 5; $attempt++) {
            self::assertSame(FailureReason::INVALID_CODE, Mfa::verify(Callers::current(self::APPLICATION), Submission::factor($factor->id, $wrong))->reason);
        }

        CarbonImmutable::setTestNow(CarbonImmutable::now()->addSeconds(30));

        self::assertSame(FailureReason::LOCKED, Mfa::verify(Callers::current(self::ADMIN), Submission::factor($factor->id, AuthenticatorApp::code($factor)))->reason);
    }

    /**
     * @param  \Illuminate\Routing\Router  $router
     * @return void
     */
    #[\Override]
    protected function defineRoutes(mixed $router): void
    {
        $router->get(self::WEB_GATED, static fn (): string => 'reached')->middleware(['auth:' . self::APPLICATION, 'mfa']);
        $router->get(self::ADMIN_GATED, static fn (): string => 'reached')->middleware(['auth:' . self::ADMIN, 'mfa']);
    }

    /**
     * Signed in to both, having enrolled TOTP through `web`.
     *
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     *
     * @throws \Throwable
     */
    private function enrolledThroughWeb(): Factor
    {
        $user = $this->person();

        Auth::guard(self::APPLICATION)->login($user);

        $this->container()->instance(Reauthenticator::class, new FreshReauthenticator($this->container()->make(ProofStore::class)));

        $start = $this->startedTotp();

        self::assertTrue(Mfa::confirmEnrollment(Callers::current(self::APPLICATION), $this->grantOf($start), $this->appCode($start))->isConfirmed());

        Auth::guard(self::ADMIN)->login($user);

        $factor = $this->pendingFactorOf($start);

        self::assertSame(self::APPLICATION, $factor->application);

        return $factor;
    }
}
