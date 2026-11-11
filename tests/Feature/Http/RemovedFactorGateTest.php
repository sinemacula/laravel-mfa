<?php

declare(strict_types = 1);

namespace Tests\Feature\Http;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\IdentityRequirement;
use SineMacula\Laravel\Mfa\Contracts\SessionTransition;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Exceptions\InsufficientAuthenticationException;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Http\Middleware\EnsureMfaRequirementIsMet;
use SineMacula\Laravel\Mfa\Http\MiddlewareSessionTransition;
use SineMacula\Laravel\Mfa\Lifecycle\FactorRemoval;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use SineMacula\Laravel\Mfa\Verification\Submission;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Requirements\FixedIdentityRequirement;
use Tests\Fixtures\Verification\Concerns\ArrangesVerification;
use Tests\TestCase;

/**
 * Removing the factor that proved AAL2 leaves a recent email proof that does
 * not reach AAL2, so the gate refuses the next request.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EnsureMfaRequirementIsMet::class)]
#[CoversClass(FactorRemoval::class)]
#[CoversClass(MiddlewareSessionTransition::class)]
final class RemovedFactorGateTest extends TestCase
{
    use ArrangesVerification;

    /** @var string Route behind `mfa`. */
    private const string GATED = 'gate/account';

    /** @var array<string, array<string, ?string>> AAL2 at any age, serialised. */
    private const array AAL2 = ['minimum_level' => ['level' => 'aal2', 'max_age' => null]];

    /**
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeVerification();

        $this->container()->instance(IdentityRequirement::class, new FixedIdentityRequirement(Requirement::none()->withMinimumLevel(AssuranceLevel::AAL2)));
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testARecentWeakerProofDoesNotPassAfterTheStrongerFactorIsRemoved(): void
    {
        [$user, $totp] = $this->personProvedWithBothFactors();

        $this->get(self::GATED)->assertOk();

        $transition = $this->container()->make(SessionTransition::class);

        self::assertInstanceOf(MiddlewareSessionTransition::class, $transition);

        $result = Mfa::removeFactor(Callers::current(), $totp->id);

        self::assertTrue($result->wasMade());
        self::assertSame(self::AAL2, $result->outstanding?->toArray());
        self::assertFalse(Factor::query()->whereKey($totp->id)->exists());

        self::assertCount(1, $this->furtherProofs($user));
        self::assertSame('email', $this->furtherProofs($user)[0]->method);

        $refusal = $this->get(self::GATED)->exception;

        self::assertInstanceOf(InsufficientAuthenticationException::class, $refusal);
        self::assertSame(self::AAL2, $refusal->requirement->toArray());
        self::assertSame(['aal2'], $refusal->acrValues());
        self::assertTrue($refusal->hasConfirmedFactor);
        self::assertCount(1, $refusal->offered);
        self::assertSame('email', $refusal->offered[0]->type);
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testRemovingTheWeakerFactorLeavesTheGateOpen(): void
    {
        $user = $this->signedInPerson();

        $this->recordFirstFactor($user);

        $totp  = $this->totpFactor($user, ['application' => self::APPLICATION]);
        $email = $this->emailFactor($user, attributes: ['application' => self::APPLICATION]);

        self::assertTrue(Mfa::verify(Callers::current(), Submission::factor($totp->id, AuthenticatorApp::code($totp)))->isVerified());

        $result = Mfa::removeFactor(Callers::current(), $email->id);

        self::assertTrue($result->wasMade());
        self::assertNull($result->outstanding);

        $this->get(self::GATED)->assertOk();
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
     * Proves TOTP then email, so the email proof is the newest.
     *
     * @return array{\Tests\Fixtures\Identities\TestUser, \SineMacula\Laravel\Mfa\Models\Factor}
     *
     * @throws \Throwable
     */
    private function personProvedWithBothFactors(): array
    {
        $user = $this->signedInPerson();

        $this->recordFirstFactor($user);

        $totp  = $this->totpFactor($user, ['application' => self::APPLICATION]);
        $email = $this->emailFactor($user, attributes: ['application' => self::APPLICATION]);

        self::assertTrue(Mfa::verify(Callers::current(), Submission::factor($totp->id, AuthenticatorApp::code($totp)))->isVerified());

        [$challenge, $code] = $this->sentCode($email);

        self::assertTrue(Mfa::verify(Callers::current(), Submission::challenge($email->id, $challenge, $code))->isVerified());

        return [$user, $totp];
    }
}
