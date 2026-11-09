<?php

declare(strict_types = 1);

namespace Tests\Feature\Requirements;

use Illuminate\Contracts\Auth\Authenticatable;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Contracts\SubjectTypeResolver;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Enums\FactorStatus;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Requirements\StepUpRefusal;
use Tests\Fixtures\Verification\Concerns\ArrangesVerification;
use Tests\TestCase;

/**
 * `Mfa::stepUpRefusal()`: the refusal the route gate raises, built for a caller
 * and a requirement given, without a request.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(StepUpRefusal::class)]
#[CoversClass(MfaManager::class)]
final class StepUpRefusalTest extends TestCase
{
    use ArrangesVerification;

    /** @var string An operation the application asks freshness for. */
    private const string CLOSE_BOOKS = 'billing.close_books';

    /**
     * Arrange the application.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeVerification();
    }

    /**
     * A person with a confirmed factor is offered it and reported as holding
     * one, under the requirement and operation given.
     *
     * @return void
     */
    public function testAPersonWithAConfirmedFactor(): void
    {
        $user = $this->signedInPerson();

        $this->totpFactor($user);

        $refusal = Mfa::stepUpRefusal(CallerContext::forIdentity($user, self::APPLICATION), Requirement::none()->withMinimumLevel(AssuranceLevel::AAL2), self::CLOSE_BOOKS);

        self::assertSame(['minimum_level' => ['level' => 'aal2', 'max_age' => null]], $refusal->requirement->toArray());
        self::assertSame(self::CLOSE_BOOKS, $refusal->operation);
        self::assertTrue($refusal->hasConfirmedFactor);
        self::assertCount(1, $refusal->offered);
        self::assertContainsOnlyInstancesOf(FactorSummary::class, $refusal->offered);
    }

    /**
     * A person whose only factor is not confirmed is reported as holding none.
     *
     * @return void
     */
    public function testAPersonWithoutAConfirmedFactor(): void
    {
        $user = $this->signedInPerson();

        $this->totpFactor($user, ['status' => FactorStatus::PENDING->value]);

        $refusal = Mfa::stepUpRefusal(CallerContext::forIdentity($user, self::APPLICATION), Requirement::none()->withAdditionalVerification());

        self::assertFalse($refusal->hasConfirmedFactor);
        self::assertNull($refusal->operation);
    }

    /**
     * The requirement is taken as given: the application's own requirement is
     * not folded in, and the operation adds no freshness.
     *
     * @return void
     */
    public function testTheRequirementIsTakenAsGiven(): void
    {
        $this->enableApplication(['requirement' => 'always', 'freshness' => [self::CLOSE_BOOKS => 300]]);

        $user = $this->signedInPerson();

        $this->totpFactor($user);

        $refusal = Mfa::stepUpRefusal(CallerContext::forIdentity($user, self::APPLICATION), Requirement::none(), self::CLOSE_BOOKS);

        self::assertSame([], $refusal->requirement->toArray());
        self::assertSame(self::CLOSE_BOOKS, $refusal->operation);
    }

    /**
     * A pending caller is offered its pending session's factors and reported by
     * its pending identity.
     *
     * @return void
     */
    public function testAPendingCaller(): void
    {
        $user = $this->person();

        $this->totpFactor($user);

        $pending = $this->pendingSession($user, Requirement::none()->withAdditionalVerification());

        $refusal = Mfa::stepUpRefusal(CallerContext::forPending($pending), $pending->requirement);

        self::assertSame(['additional_verification' => ['max_age' => null]], $refusal->requirement->toArray());
        self::assertTrue($refusal->hasConfirmedFactor);
        self::assertCount(1, $refusal->offered);
    }

    /**
     * A caller serving nobody, or an identity that is not a person, is offered
     * nothing and reported as holding no confirmed factor, even one it holds.
     *
     * @return void
     */
    public function testACallerNotServedHasNothing(): void
    {
        $user = $this->signedInPerson();

        $this->totpFactor($user);
        $this->noPersons();

        foreach ([CallerContext::nobody(self::APPLICATION), CallerContext::forIdentity($user, self::APPLICATION)] as $caller) {

            $refusal = Mfa::stepUpRefusal($caller, Requirement::none()->withAdditionalVerification());

            self::assertFalse($refusal->hasConfirmedFactor);
            self::assertSame([], $refusal->offered);
        }
    }

    /**
     * A pending caller is reported by its pending identity whatever it is, as
     * the gate reports it, though it is offered nothing when it is not a person
     * or its credential may not list factors.
     *
     * @return void
     */
    public function testAPendingCallerIsReportedThoughOfferedNothing(): void
    {
        $user = $this->person();

        $this->totpFactor($user);

        $unlisted = $this->pendingSession($user, Requirement::none()->withAdditionalVerification(), [PendingAction::VERIFY]);
        $refusal  = Mfa::stepUpRefusal(CallerContext::forPending($unlisted), $unlisted->requirement);

        self::assertTrue($refusal->hasConfirmedFactor);
        self::assertSame([], $refusal->offered);

        $pending = $this->pendingSession($user, Requirement::none()->withAdditionalVerification());

        $this->noPersons();

        $refusal = Mfa::stepUpRefusal(CallerContext::forPending($pending), $pending->requirement);

        self::assertTrue($refusal->hasConfirmedFactor);
        self::assertSame([], $refusal->offered);
    }

    /**
     * Bind a subject type resolver that finds no identity a person.
     *
     * @return void
     */
    private function noPersons(): void
    {
        $this->container()->instance(SubjectTypeResolver::class, new class implements SubjectTypeResolver {
            /**
             * Whether the identity is a person: never.
             *
             * @param  \Illuminate\Contracts\Auth\Authenticatable  $identity
             * @return bool
             */
            #[\Override]
            public function isPerson(Authenticatable $identity): bool
            {
                return false;
            }
        });
    }
}
