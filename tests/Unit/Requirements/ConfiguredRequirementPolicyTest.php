<?php

declare(strict_types = 1);

namespace Tests\Unit\Requirements;

use Illuminate\Foundation\Testing\RefreshDatabase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Assurance\Evaluation;
use SineMacula\Laravel\Mfa\Contracts\RequirementCheck;
use SineMacula\Laravel\Mfa\Contracts\RequirementPolicy;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Requirements\ConfiguredRequirementPolicy;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use Tests\Fixtures\Identities\NonEloquentIdentity;
use Tests\Fixtures\Requirements\SignInProofs;
use Tests\TestCase;

/**
 * Tests for `ConfiguredRequirementPolicy`: after the first factor, the sign-in
 * must meet the requirement composed from the application's mode and the
 * identity's own, unless the first factor meets all of it on its own, as a
 * passkey that verified the person meets an additional verification. A proof
 * that is not the identity's first factor on the application suppresses
 * nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConfiguredRequirementPolicy::class)]
final class ConfiguredRequirementPolicyTest extends TestCase
{
    use RefreshDatabase;

    /**
     * Rows of the application's mode, the identity's own requirement, the
     * first factor as the sign-in made it, and the requirement the sign-in
     * must still meet, serialised.
     *
     * @return iterable<string, array{string, ?\SineMacula\Laravel\Mfa\Requirements\Requirement, \Closure(\Tests\Fixtures\Requirements\SignInProofs): \SineMacula\Laravel\Mfa\Proofs\Proof, array<string, array<string, int|string|null>>}>
     */
    public static function signIns(): iterable
    {
        $additional = ['additional_verification' => ['max_age' => null]];
        $aal3       = Requirement::none()->withMinimumLevel(AssuranceLevel::AAL3);

        yield 'a password, always' => ['always', null, static fn (SignInProofs $signIn): Proof => $signIn->password(), $additional];
        yield 'a passkey that verified the person, always' => ['always', null, static fn (SignInProofs $signIn): Proof => $signIn->passkey(true), []];
        yield 'a passkey that did not verify the person, always' => ['always', null, static fn (SignInProofs $signIn): Proof => $signIn->passkey(false), $additional];
        yield 'a passkey that verified the person, under AAL3' => [
            'always',
            $aal3,
            static fn (SignInProofs $signIn): Proof => $signIn->passkey(true),
            ['additional_verification' => ['max_age' => null], 'minimum_level' => ['level' => 'aal3', 'max_age' => null]],
        ];
        yield 'a password, never' => ['never', null, static fn (SignInProofs $signIn): Proof => $signIn->password(), []];
        yield 'a passkey that verified the person, on another application' => [
            'always',
            null,
            static fn (SignInProofs $signIn): Proof => $signIn->onApplication('admin')->passkey(true),
            $additional,
        ];
        yield 'a passkey that verified another identity' => [
            'always',
            null,
            static fn (SignInProofs $signIn): Proof => $signIn->ofIdentity('plain-2')->passkey(true),
            $additional,
        ];
    }

    /**
     * The sign-in must meet the whole composed requirement unless the first
     * factor meets all of it on its own.
     *
     * @param  string  $mode
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $own
     * @param  \Closure(\Tests\Fixtures\Requirements\SignInProofs): \SineMacula\Laravel\Mfa\Proofs\Proof  $firstFactor
     * @param  array<string, array<string, int|string|null>>  $expected
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('signIns')]
    public function testAsksForWhatTheFirstFactorDoesNotMeet(string $mode, ?Requirement $own, \Closure $firstFactor, array $expected): void
    {
        $this->configureApplication($mode);

        $identity = new NonEloquentIdentity('plain-1', requirement: $own);

        $requirement = $this->policy()->requirementFor($identity, SignInProofs::APPLICATION, $firstFactor(SignInProofs::of($identity)));

        self::assertSame($expected, $requirement->toArray());
    }

    /**
     * A proof that is not a first factor suppresses nothing, even when the
     * bound check finds it meets the requirement.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAProofThatIsNoFirstFactorSuppressesNothing(): void
    {
        $this->configureApplication('always');
        $this->container()->instance(RequirementCheck::class, self::checkMeetingEverything());

        $identity = new NonEloquentIdentity('plain-1');
        $signIn   = SignInProofs::of($identity);

        self::assertFalse($this->policy()->requirementFor($identity, SignInProofs::APPLICATION, $signIn->passkeyReauthentication())->isEmpty());
        self::assertTrue($this->policy()->requirementFor($identity, SignInProofs::APPLICATION, $signIn->password())->isEmpty());
    }

    /**
     * The policy is the default the container binds.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testIsTheBoundPolicy(): void
    {
        self::assertInstanceOf(ConfiguredRequirementPolicy::class, $this->container()->make(RequirementPolicy::class));
    }

    /**
     * Configure the application the sign-ins are on with the given mode.
     *
     * @param  string  $mode
     * @return void
     */
    private function configureApplication(string $mode): void
    {
        config()->set('mfa.applications.' . SignInProofs::APPLICATION, [
            'requirement'  => $mode,
            'first_factor' => ['method' => 'password', 'channel' => 'password'],
        ]);
    }

    /**
     * Resolve the policy under test.
     *
     * @return \SineMacula\Laravel\Mfa\Requirements\ConfiguredRequirementPolicy
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function policy(): ConfiguredRequirementPolicy
    {
        return $this->container()->make(ConfiguredRequirementPolicy::class);
    }

    /**
     * A check that finds every requirement met by any proofs.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\RequirementCheck
     */
    private static function checkMeetingEverything(): RequirementCheck
    {
        return new class implements RequirementCheck {
            /**
             * Find the requirement met.
             *
             * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
             * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  ...$proofs
             * @return \SineMacula\Laravel\Mfa\Assurance\Evaluation
             */
            #[\Override]
            public function check(Requirement $requirement, Proof ...$proofs): Evaluation
            {
                return new Evaluation(true, true, AssuranceLevel::AAL2, true, false, ['mfa'], $requirement->parts(), []);
            }
        };
    }
}
