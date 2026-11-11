<?php

declare(strict_types = 1);

namespace Tests\Unit\Requirements;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Contracts\CombinationPolicy;
use SineMacula\Laravel\Mfa\Contracts\RequirementCheck;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Enums\RequirementPart;
use SineMacula\Laravel\Mfa\Requirements\ProofRequirementCheck;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use Tests\Fixtures\Requirements\RecordingCombinationPolicy;
use Tests\Fixtures\Requirements\SignInProofs;
use Tests\TestCase;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ProofRequirementCheck::class)]
final class ProofRequirementCheckTest extends TestCase
{
    /** @var int The maximum age of a fresh step-up, in seconds. */
    private const int FRESH = 900;

    /** @var int The age of a proof made two hours ago, in seconds. */
    private const int TWO_HOURS = 7200;

    /**
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        CarbonImmutable::setTestNow('2026-11-01T12:00:00.000000+00:00');
    }

    /**
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * @return iterable<string, array{
     *     \SineMacula\Laravel\Mfa\Requirements\Requirement,
     *     \Closure(\Tests\Fixtures\Requirements\SignInProofs): list<\SineMacula\Laravel\Mfa\Proofs\Proof>,
     *     list<\SineMacula\Laravel\Mfa\Enums\RequirementPart>,
     *     list<\SineMacula\Laravel\Mfa\Enums\RequirementPart>,
     * }>
     */
    public static function judgments(): iterable
    {
        $additional = Requirement::none()->withAdditionalVerification(self::FRESH);
        $aal1       = Requirement::none()->withMinimumLevel(AssuranceLevel::AAL1, self::FRESH);
        $aal2       = Requirement::none()->withMinimumLevel(AssuranceLevel::AAL2, self::FRESH);
        $mfa        = Requirement::none()->withMultifactor(self::FRESH);

        $none = [];
        $av   = [RequirementPart::ADDITIONAL_VERIFICATION];
        $ml   = [RequirementPart::MINIMUM_LEVEL];
        $mf   = [RequirementPart::MULTIFACTOR];

        yield 'an empty requirement, with no proofs' => [Requirement::none(), static fn (SignInProofs $signIn): array => [], $none, $none];
        yield 'an empty requirement, with a sign-in' => [Requirement::none(), static fn (SignInProofs $signIn): array => [$signIn->password()], $none, $none];
        yield 'an old AAL2 combination and a fresh password reauthentication' => [
            $aal2,
            static fn (SignInProofs $signIn): array => [$signIn->password(self::TWO_HOURS), $signIn->totp(self::TWO_HOURS), $signIn->reauthentication()],
            $none,
            $ml,
        ];
        yield 'an old TOTP code and a fresh email code' => [
            $mfa,
            static fn (SignInProofs $signIn): array => [$signIn->password(self::TWO_HOURS), $signIn->totp(self::TWO_HOURS), $signIn->email()],
            $none,
            $mf,
        ];
        yield 'a fresh TOTP code after an old password' => [
            $mfa,
            static fn (SignInProofs $signIn): array => [$signIn->password(self::TWO_HOURS), $signIn->totp()],
            $mf,
            $none,
        ];
        yield 'a fresh TOTP code after an old password, at AAL2' => [
            $aal2,
            static fn (SignInProofs $signIn): array => [$signIn->password(self::TWO_HOURS), $signIn->totp()],
            $ml,
            $none,
        ];
        yield 'a fresh password reauthentication' => [
            $additional,
            static fn (SignInProofs $signIn): array => [$signIn->password(self::TWO_HOURS), $signIn->reauthentication()],
            $none,
            $av,
        ];
        yield 'a fresh password first factor alone' => [$additional, static fn (SignInProofs $signIn): array => [$signIn->password()], $none, $av];
        yield 'a fresh password reauthentication, at AAL1' => [
            $aal1,
            static fn (SignInProofs $signIn): array => [$signIn->password(self::TWO_HOURS), $signIn->reauthentication()],
            $ml,
            $none,
        ];
        yield 'a fresh passkey reauthentication that verified the person' => [
            $additional,
            static fn (SignInProofs $signIn): array => [$signIn->password(self::TWO_HOURS), $signIn->passkeyReauthentication()],
            $av,
            $none,
        ];
        yield 'a fresh external reauthentication, for an additional verification' => [
            $additional,
            static fn (SignInProofs $signIn): array => [$signIn->externalProvider(self::TWO_HOURS), $signIn->totp(self::TWO_HOURS), $signIn->externalReauthentication()],
            $none,
            $av,
        ];
        yield 'a fresh external reauthentication, for a level' => [
            $aal1,
            static fn (SignInProofs $signIn): array => [$signIn->externalProvider(self::TWO_HOURS), $signIn->totp(self::TWO_HOURS), $signIn->externalReauthentication()],
            $none,
            $ml,
        ];
        yield 'a fresh TOTP code of another sign-in' => [
            $additional,
            static fn (SignInProofs $signIn): array => [$signIn->password(), $signIn->inSession('sign-in-2')->totp()],
            $none,
            $av,
        ];
        yield 'a fresh TOTP code of the same sign-in' => [$additional, static fn (SignInProofs $signIn): array => [$signIn->password(), $signIn->totp()], $av, $none];
        yield 'a TOTP code with no first factor' => [$additional, static fn (SignInProofs $signIn): array => [$signIn->totp()], $none, $av];
        yield 'a TOTP code after two first factors' => [
            $additional,
            static fn (SignInProofs $signIn): array => [$signIn->password(), $signIn->inSession('sign-in-2')->password(), $signIn->totp()],
            $none,
            $av,
        ];
    }

    /**
     * Met only by a proof that provides the part within its maximum age.
     *
     * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @param  \Closure(\Tests\Fixtures\Requirements\SignInProofs): list<\SineMacula\Laravel\Mfa\Proofs\Proof>  $proofs
     * @param  list<\SineMacula\Laravel\Mfa\Enums\RequirementPart>  $met
     * @param  list<\SineMacula\Laravel\Mfa\Enums\RequirementPart>  $unmet
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('judgments')]
    public function testJudgesEachPartOnTheProofsOfOneSignIn(Requirement $requirement, \Closure $proofs, array $met, array $unmet): void
    {
        $evaluation = $this->check()->check($requirement, ...$proofs(new SignInProofs));

        self::assertSame($met, $evaluation->met);
        self::assertSame($unmet, $evaluation->unmet);
        self::assertSame($unmet === [], $evaluation->meetsRequirement());
    }

    /**
     * In the order given; none reach it without exactly one first factor.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testHandsOnlyTheSignInsProofsToTheBoundPolicy(): void
    {
        $signIn = new SignInProofs;
        $first  = $signIn->password();
        $totp   = $signIn->totp();
        $other  = $signIn->inSession('sign-in-2')->totp();
        $policy = new RecordingCombinationPolicy;

        $this->container()->instance(CombinationPolicy::class, $policy);

        $this->check()->check(Requirement::none(), $other, $first, $totp);
        $this->check()->check(Requirement::none(), $totp, $other);

        self::assertSame([[$first, $totp], []], $policy->handed);
    }

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testIsTheBoundCheck(): void
    {
        self::assertInstanceOf(ProofRequirementCheck::class, $this->container()->make(RequirementCheck::class));
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Requirements\ProofRequirementCheck
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function check(): ProofRequirementCheck
    {
        return $this->container()->make(ProofRequirementCheck::class);
    }
}
