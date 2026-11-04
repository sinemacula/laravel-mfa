<?php

declare(strict_types = 1);

namespace Tests\Unit\Requirements;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\IdentityRequirement;
use SineMacula\Laravel\Mfa\Contracts\SessionTransition;
use SineMacula\Laravel\Mfa\Enums\FactorChangeMade;
use SineMacula\Laravel\Mfa\Enums\FactorStatus;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Requirements\SessionReevaluation;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Requirements\FixedIdentityRequirement;
use Tests\Fixtures\Requirements\SignInProofs;
use Tests\Fixtures\Seams\RecordingSessionTransition;
use Tests\TestCase;

/**
 * Tests for `SessionReevaluation`: a judgement hands every change to the bound
 * session transition, with the requirement the session no longer meets or none,
 * and returns the package's assessment with what the transition returned; an
 * assessment alone calls no seam.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionReevaluation::class)]
final class SessionReevaluationTest extends TestCase
{
    /**
     * Met or not, the change goes to the transition as made, and the judgement
     * carries the assessment and the transition's answer.
     *
     * @return void
     */
    public function testEveryChangeGoesToTheTransition(): void
    {
        /** @var \Tests\Fixtures\Identities\TestUser $user */
        $user        = TestUser::query()->firstOrCreate(['email' => 'judged@example.test']);
        $factor      = new FactorSummary('factor-totp', 'totp', null, null, FactorStatus::CONFIRMED, false, null);
        $completion  = new \stdClass;
        $transition  = new RecordingSessionTransition($completion);
        $requirement = Requirement::none()->withAdditionalVerification();
        $password    = [SignInProofs::of($user)->password()];

        $this->container()->instance(SessionTransition::class, $transition);

        $met = $this->reevaluation()->judge($user, 'web', SignInProofs::SESSION, FactorChangeMade::CONFIRMED, $factor, $password);

        self::assertNull($met->outstanding);
        self::assertSame($completion, $met->completion());

        $this->container()->instance(IdentityRequirement::class, new FixedIdentityRequirement($requirement));

        $short = $this->reevaluation()->judge($user, 'web', SignInProofs::SESSION, FactorChangeMade::REMOVED, $factor, $password);

        self::assertSame($requirement->toArray(), $short->outstanding?->toArray());
        self::assertCount(2, $transition->changes);

        [$first, $second] = $transition->changes;

        self::assertSame($user, $first->identity);
        self::assertSame('web', $first->application);
        self::assertSame(SignInProofs::SESSION, $first->session);
        self::assertSame(FactorChangeMade::CONFIRMED, $first->change);
        self::assertSame($factor, $first->factor);
        self::assertNull($first->outstanding);
        self::assertSame(FactorChangeMade::REMOVED, $second->change);
        self::assertSame($requirement->toArray(), $second->outstanding?->toArray());
    }

    /**
     * An assessment alone calls no seam.
     *
     * @return void
     */
    public function testAnAssessmentAloneCallsNoSeam(): void
    {
        /** @var \Tests\Fixtures\Identities\TestUser $user */
        $user       = TestUser::query()->firstOrCreate(['email' => 'assessed@example.test']);
        $transition = new RecordingSessionTransition;

        $this->container()->instance(SessionTransition::class, $transition);
        $this->container()->instance(IdentityRequirement::class, new FixedIdentityRequirement(Requirement::none()->withAdditionalVerification()));

        self::assertNotNull($this->reevaluation()->outstanding($user, 'web', [SignInProofs::of($user)->password()]));
        self::assertSame([], $transition->changes);
    }

    /**
     * The reevaluation under test.
     *
     * @return \SineMacula\Laravel\Mfa\Requirements\SessionReevaluation
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function reevaluation(): SessionReevaluation
    {
        return $this->container()->make(SessionReevaluation::class);
    }
}
