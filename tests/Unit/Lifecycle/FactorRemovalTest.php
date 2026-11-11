<?php

declare(strict_types = 1);

namespace Tests\Unit\Lifecycle;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\IdentityRequirement;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Contracts\SessionRevoker;
use SineMacula\Laravel\Mfa\Contracts\SessionTransition;
use SineMacula\Laravel\Mfa\Enums\FactorChangeMade;
use SineMacula\Laravel\Mfa\Exceptions\UnsupportedFactorException;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Lifecycle\FactorRemoval;
use SineMacula\Laravel\Mfa\Lifecycle\FactorRemovalResult;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Models\PasskeyAssociation;
use SineMacula\Laravel\Mfa\Models\RecoveryCode;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Factors\FactorSets;
use Tests\Fixtures\Lifecycle\Concerns\ArrangesLifecycle;
use Tests\Fixtures\Lifecycle\RecordingSessionRevoker;
use Tests\Fixtures\Requirements\FixedIdentityRequirement;
use Tests\Fixtures\Requirements\SignInProofs;
use Tests\Fixtures\Seams\InterceptedProofStore;
use Tests\Fixtures\Seams\RecordingSessionTransition;
use Tests\TestCase;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FactorRemoval::class)]
final class FactorRemovalTest extends TestCase
{
    use ArrangesLifecycle;

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testARemovalOutsideATransactionIsRefused(): void
    {
        $this->enablePasskeys();

        $user   = $this->signedInPerson();
        $factor = $this->confirmedFactor($user);

        try {
            $this->removal()->remove($user, self::APPLICATION, $factor, FactorSets::of($factor), SignInProofs::SESSION);
            self::fail('A removal outside a transaction was expected to be refused.');
        } catch (\LogicException $exception) {
            self::assertSame('A factor is removed only inside the identity\'s factor state transaction.', $exception->getMessage());
        }

        self::assertTrue(Factor::query()->whereKey($factor->id)->exists());
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFactorWithNoIdIsRefused(): void
    {
        $this->enablePasskeys();

        $user   = $this->signedInPerson();
        $factor = $this->confirmedFactor($user)->replicate();

        $this->expectException(UnsupportedFactorException::class);
        $this->expectExceptionMessage('A factor is removed by its id.');

        DB::transaction(fn () => $this->removal()->remove($user, self::APPLICATION, $factor, FactorSets::of($factor), SignInProofs::SESSION));
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testErasingDeletesOnlyTheFactorsOwnRecords(): void
    {
        $this->enablePasskeys();

        $user    = $this->signedInPerson();
        $other   = $this->confirmedFactor($user);
        $passkey = $this->confirmedFactor($user, 'passkey', self::CREDENTIAL);

        $this->stepUpWith($user, $other);
        $this->stepUpWith($user, $passkey);

        $generation = VerificationGeneration::current($user);

        $this->removal()->erase($user, $passkey);

        self::assertFalse(Factor::query()->whereKey($passkey->id)->exists());
        self::assertTrue(Factor::query()->whereKey($other->id)->exists());
        self::assertSame(0, PasskeyAssociation::query()->where('factor_id', $passkey->id)->count());
        self::assertSame($generation, VerificationGeneration::current($user));

        $proofs = $this->container()->make(ProofStore::class)->proofs($user, self::APPLICATION, self::SESSION);

        self::assertSame([$other->id], array_map(static fn (Proof $proof): ?string => $proof->reference, $proofs));
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheLastFactorTakesTheSetWithIt(): void
    {
        $this->arrangeLifecycle();

        $user   = $this->signedInPerson();
        $factor = $this->confirmedFactor($user);

        $this->stepUpWith($user, $factor);
        $this->recoveryCodesOf($user);

        self::assertTrue(Mfa::removeFactor(Callers::current(), $factor->id)->wasMade());
        self::assertSame(0, RecoveryCode::query()->count());
        self::assertSame(['FactorRemoved', 'RecoveryCodesRemoved'], $this->reportedNames());
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnotherConfirmedFactorKeepsTheSet(): void
    {
        $this->arrangeLifecycle();

        $user   = $this->signedInPerson();
        $kept   = $this->confirmedFactor($user);
        $factor = $this->confirmedFactor($user);

        $this->stepUpWith($user, $kept);
        $this->recoveryCodesOf($user);

        $stored = RecoveryCode::query()->count();

        self::assertGreaterThan(0, $stored);
        self::assertTrue(Mfa::removeFactor(Callers::current(), $factor->id)->wasMade());
        self::assertSame($stored, RecoveryCode::query()->count());
        self::assertSame(['FactorRemoved'], $this->reportedNames());
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testNoSetIsReportedWhereThereWasNone(): void
    {
        $this->arrangeLifecycle();

        $user   = $this->signedInPerson();
        $factor = $this->confirmedFactor($user);

        $this->stepUpWith($user, $factor);

        self::assertTrue(Mfa::removeFactor(Callers::current(), $factor->id)->wasMade());
        self::assertSame(['FactorRemoved'], $this->reportedNames());
    }

    /**
     * A revoker that judged the session is the only judge; otherwise the
     * session transition is.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOneJudgeOfTheSessionAnswersTheRemoval(): void
    {
        $this->enablePasskeys();

        $user       = $this->signedInPerson();
        $factor     = $this->confirmedFactor($user);
        $other      = $this->confirmedFactor($user);
        $completion = new \stdClass;
        $transition = new RecordingSessionTransition($completion);

        $this->container()->instance(SessionTransition::class, $transition);

        $factors = FactorSets::of($factor, $other);
        $result  = DB::transaction(fn (): FactorRemovalResult => $this->removal()->remove($user, self::APPLICATION, $factor, $factors, SignInProofs::SESSION));

        self::assertSame($completion, $result->completion());
        self::assertCount(1, $transition->changes);
        self::assertSame(FactorChangeMade::REMOVED, $transition->changes[0]->change);
        self::assertSame(SignInProofs::SESSION, $transition->changes[0]->session);
        self::assertSame($factor->id, $transition->changes[0]->factor->id);

        $answer = new \stdClass;

        $this->container()->instance(SessionRevoker::class, new RecordingSessionRevoker(judges: true, completion: $answer));

        $result = DB::transaction(fn (): FactorRemovalResult => $this->removal()->remove($user, self::APPLICATION, $other, FactorSets::of($other), SignInProofs::SESSION));

        self::assertSame($answer, $result->completion());
        self::assertCount(1, $transition->changes);
    }

    /**
     * The session is judged without the removed factor's proofs, even from a
     * store that still lists them.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheRemovedFactorsProofsDoNotMeetTheRequirement(): void
    {
        $requirement = Requirement::none()->withAdditionalVerification();

        $lagging = new InterceptedProofStore($this->container()->make(ProofStore::class), static function (): void {});

        $this->container()->instance(ProofStore::class, $lagging);
        $this->container()->instance(SessionRevoker::class, new RecordingSessionRevoker(judges: true));
        $this->container()->instance(IdentityRequirement::class, new FixedIdentityRequirement($requirement));

        $user   = $this->signedInPerson();
        $factor = $this->confirmedFactor($user);
        $other  = $this->confirmedFactor($user);

        $this->container()->make(ProofStore::class)->record($user, SignInProofs::of($user)->password());
        $this->stepUpWith($user, $factor);

        $factors = FactorSets::of($factor, $other);
        $result  = DB::transaction(fn (): FactorRemovalResult => $this->removal()->remove($user, self::APPLICATION, $factor, $factors, SignInProofs::SESSION));

        self::assertSame($requirement->toArray(), $result->outstanding?->toArray());
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Lifecycle\FactorRemoval
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function removal(): FactorRemoval
    {
        return $this->container()->make(FactorRemoval::class);
    }
}
