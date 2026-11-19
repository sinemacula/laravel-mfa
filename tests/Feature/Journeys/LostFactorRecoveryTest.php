<?php

declare(strict_types = 1);

namespace Tests\Feature\Journeys;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Auth;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Contracts\Reauthenticator;
use SineMacula\Laravel\Mfa\Enums\EnrollmentAuthorization;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Exceptions\InsufficientAuthenticationException;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Http\Middleware\EnsureMfaRequirementIsMet;
use SineMacula\Laravel\Mfa\Lifecycle\FactorRemoval;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService;
use SineMacula\Laravel\Mfa\Secrets\RevealedSecret;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use SineMacula\Laravel\Mfa\Verification\Submission;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Enrollment\Concerns\ArrangesEnrollment;
use Tests\Fixtures\Seams\FreshReauthenticator;
use Tests\TestCase;

/**
 * A person who lost their phone signs in with a recovery code, replaces the
 * factor and keeps passing the gate.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EnsureMfaRequirementIsMet::class)]
#[CoversClass(FactorRemoval::class)]
#[CoversClass(RecoveryCodeService::class)]
final class LostFactorRecoveryTest extends TestCase
{
    use ArrangesEnrollment;

    /** @var string Route behind `mfa`. */
    private const string GATED = 'gate/account';

    /** @var string Route behind `mfa:level=aal2`. */
    private const string AAL2 = 'gate/billing';

    /**
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeVerification();
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testOnAnEnrolledApplicationTheLostFactorIsRemovedAndReplaced(): void
    {
        $this->enableApplication(['types' => ['totp'], 'requirement' => 'enrolled']);

        [$lost, $codes] = $this->recoveredWithACode();

        self::assertTrue(Mfa::removeFactor(Callers::current(), $lost->id)->wasMade());
        self::assertFalse(Mfa::recoveryCodeStatus(Callers::current())?->exists());

        $start = $this->startedTotp();

        self::assertSame(EnrollmentAuthorization::REAUTHENTICATION, $this->rowOf($start)->authority);

        $confirmation = Mfa::confirmEnrollment(Callers::current(), $this->grantOf($start), $this->appCode($start));

        self::assertTrue($confirmation->isConfirmed());
        self::assertCount(10, $confirmation->recoveryCodes);
        self::assertSame(10, Mfa::recoveryCodeStatus(Callers::current())->remaining);

        foreach ($codes as $code) {
            self::assertSame(FailureReason::INVALID_CODE, Mfa::verify(Callers::current(), Submission::recoveryCode($code), Purpose::SIGN_IN)->reason);
        }

        $replacement = $this->pendingFactorOf($start);

        CarbonImmutable::setTestNow(CarbonImmutable::now()->addSeconds(30));

        self::assertTrue(Mfa::verify(Callers::current(), Submission::recoveryCode($confirmation->recoveryCodes[0]->reveal()))->isVerified());
        self::assertTrue(Mfa::verify(Callers::current(), Submission::factor($replacement->id, AuthenticatorApp::code($replacement)))->isVerified());

        $this->get(self::GATED)->assertOk();
    }

    /**
     * The last factor stays until the new one is confirmed.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOnAnAlwaysApplicationTheNewFactorIsConfirmedBeforeTheLostOneGoes(): void
    {
        $this->enableApplication(['types' => ['totp'], 'requirement' => 'always']);

        [$lost] = $this->recoveredWithACode();

        self::assertSame(FailureReason::LAST_FACTOR, Mfa::removeFactor(Callers::current(), $lost->id)->reason);

        $start = $this->startedTotp();

        self::assertSame(EnrollmentAuthorization::STEP_UP, $this->rowOf($start)->authority);

        $confirmation = Mfa::confirmEnrollment(Callers::current(), $this->grantOf($start), $this->appCode($start));

        self::assertTrue($confirmation->isConfirmed());
        self::assertSame([], $confirmation->recoveryCodes);
        self::assertTrue(Mfa::removeFactor(Callers::current(), $lost->id)->wasMade());
        self::assertSame(9, Mfa::recoveryCodeStatus(Callers::current())?->remaining);

        $this->get(self::GATED)->assertOk();
        $this->get(self::AAL2)->assertOk();
    }

    /**
     * @param  \Illuminate\Routing\Router  $router
     * @return void
     */
    #[\Override]
    protected function defineRoutes(mixed $router): void
    {
        $router->get(self::GATED, static fn (): string => 'reached')->middleware('mfa');
        $router->get(self::AAL2, static fn (): string => 'reached')->middleware('mfa:level=aal2');
    }

    /**
     * Signs in, enrols TOTP with its recovery codes, is refused with the TOTP
     * offered, then signs in with the first code.
     *
     * @return array{\SineMacula\Laravel\Mfa\Models\Factor, list<string>}
     *
     * @throws \Throwable
     */
    private function recoveredWithACode(): array
    {
        $user = $this->person();

        Auth::login($user);

        $this->container()->instance(Reauthenticator::class, new FreshReauthenticator($this->container()->make(ProofStore::class)));

        $start        = $this->startedTotp();
        $confirmation = Mfa::confirmEnrollment(Callers::current(), $this->grantOf($start), $this->appCode($start));
        $codes        = array_map(static fn (RevealedSecret $code): string => $code->reveal(), $confirmation->recoveryCodes);
        $factor       = Factor::query()->whereKey($start->factor?->id)->sole();

        self::assertCount(10, $codes);

        $refusal = $this->get(self::GATED)->exception;

        self::assertInstanceOf(InsufficientAuthenticationException::class, $refusal);
        self::assertSame([$factor->id], array_column($refusal->offered, 'id'));

        self::assertTrue(Mfa::verify(Callers::current(), Submission::recoveryCode($codes[0]), Purpose::SIGN_IN)->isVerified());

        $this->get(self::GATED)->assertOk();
        $this->get(self::AAL2)->assertOk();

        return [$factor, $codes];
    }
}
