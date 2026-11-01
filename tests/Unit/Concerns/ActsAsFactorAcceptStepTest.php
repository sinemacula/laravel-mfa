<?php

declare(strict_types = 1);

namespace Tests\Unit\Concerns;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Mfa\Concerns\ActsAsFactor;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\Drivers\AuthenticatorApp;
use Tests\TestCase;

/**
 * Unit tests for `ActsAsFactor::acceptStep()`: the compare-and-set of a TOTP
 * factor's last accepted time step, on a stored row and on a factor not yet
 * stored, and that a stale copy of the factor can neither record a step
 * another copy recorded nor write an older one back over it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversTrait(ActsAsFactor::class)]
final class ActsAsFactorAcceptStepTest extends TestCase
{
    use RefreshDatabase;

    /** @var int A time step to record. */
    private const int STEP = 60000000;

    /**
     * A stored factor records its first step, then each later one, in its row.
     *
     * @return void
     */
    public function testAStoredFactorRecordsItsFirstAndEachLaterStep(): void
    {
        $factor = $this->storedFactor();

        self::assertTrue($factor->acceptStep(self::STEP));
        self::assertSame(self::STEP, $factor->getLastAcceptedStep());
        self::assertSame(self::STEP, $this->storedStep($factor));

        self::assertTrue($factor->acceptStep(self::STEP + 1));
        self::assertSame(self::STEP + 1, $factor->getLastAcceptedStep());
        self::assertSame(self::STEP + 1, $this->storedStep($factor));
    }

    /**
     * A stored factor refuses its last step and any earlier one, leaving its
     * row as it was.
     *
     * @return void
     */
    public function testAStoredFactorRefusesTheSameOrAnEarlierStep(): void
    {
        $factor = $this->storedFactor();

        self::assertTrue($factor->acceptStep(self::STEP));
        self::assertFalse($factor->acceptStep(self::STEP));
        self::assertFalse($factor->acceptStep(self::STEP - 1));
        self::assertSame(self::STEP, $factor->getLastAcceptedStep());
        self::assertSame(self::STEP, $this->storedStep($factor));
    }

    /**
     * A copy of the factor read before another copy recorded a step cannot
     * record the same step: the row as stored decides, not the copy.
     *
     * @return void
     */
    public function testAStaleCopyCannotRecordAStepAnotherCopyRecorded(): void
    {
        $first  = $this->storedFactor();
        $second = Factor::query()->findOrFail($first->id);

        self::assertTrue($first->acceptStep(self::STEP));

        self::assertNull($second->getLastAcceptedStep());
        self::assertFalse($second->acceptStep(self::STEP));
        self::assertNull($second->getLastAcceptedStep());
        self::assertSame(self::STEP, $this->storedStep($first));
    }

    /**
     * A copy that recorded a step does not write it back when it is persisted
     * later, after another copy recorded a later step.
     *
     * @return void
     */
    public function testPersistingAfterwardsKeepsALaterStepAnotherCopyRecorded(): void
    {
        $first  = $this->storedFactor();
        $second = Factor::query()->findOrFail($first->id);

        self::assertTrue($first->acceptStep(self::STEP));
        self::assertTrue($second->acceptStep(self::STEP + 1));

        self::assertFalse($first->isDirty($first->getLastAcceptedStepName()));

        $first->setAttribute('label', 'Phone');
        $first->persist();

        self::assertSame(self::STEP + 1, $this->storedStep($first));
        self::assertSame('Phone', Factor::query()->findOrFail($first->id)->getLabel());
    }

    /**
     * Another factor's row is never touched.
     *
     * @return void
     */
    public function testOnlyTheFactorsOwnRowIsUpdated(): void
    {
        $factor = $this->storedFactor();
        $other  = $this->storedFactor();

        self::assertTrue($factor->acceptStep(self::STEP));
        self::assertNull($this->storedStep($other));
    }

    /**
     * A factor not yet stored compares with its own attribute, and the step
     * it recorded is stored with it.
     *
     * @return void
     */
    public function testAFactorNotYetStoredComparesWithItsOwnStep(): void
    {
        $factor = new Factor([
            ...AuthenticatorApp::FACTOR,
            'authenticatable_type' => 'user',
            'authenticatable_id'   => '1',
        ]);

        self::assertTrue($factor->acceptStep(self::STEP));
        self::assertFalse($factor->acceptStep(self::STEP));
        self::assertFalse($factor->acceptStep(self::STEP - 1));
        self::assertTrue($factor->acceptStep(self::STEP + 1));

        $factor->persist();

        self::assertSame(self::STEP + 1, $this->storedStep($factor));
    }

    /**
     * Store a TOTP factor with no step accepted, and read it back.
     *
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function storedFactor(): Factor
    {
        $factor = Factor::query()->create([
            ...AuthenticatorApp::FACTOR,
            'authenticatable_type' => 'user',
            'authenticatable_id'   => '1',
        ]);

        return Factor::query()->findOrFail($factor->id);
    }

    /**
     * The step stored in the factor's row.
     *
     * @param  \SineMacula\Laravel\Mfa\Models\Factor  $factor
     * @return ?int
     */
    private function storedStep(Factor $factor): ?int
    {
        $step = DB::table('mfa_factors')->where('id', $factor->id)->value('last_accepted_step');

        return $step === null ? null : (int) $step;
    }
}
