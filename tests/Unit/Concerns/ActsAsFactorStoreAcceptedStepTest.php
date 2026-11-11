<?php

declare(strict_types = 1);

namespace Tests\Unit\Concerns;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Mfa\Concerns\ActsAsFactor;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Support\FactorStateTransaction;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use Tests\Fixtures\Exceptions\MidRotationFailureException;
use Tests\TestCase;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversTrait(ActsAsFactor::class)]
final class ActsAsFactorStoreAcceptedStepTest extends TestCase
{
    use RefreshDatabase;

    /** @var int A time step to record. */
    private const int STEP = 60000000;

    /**
     * @return void
     */
    public function testAStoredFactorRecordsItsFirstAndEachLaterStep(): void
    {
        $factor = $this->storedFactor();

        self::assertTrue($factor->storeAcceptedStep(self::STEP));
        self::assertSame(self::STEP, $factor->getLastAcceptedStep());
        self::assertSame(self::STEP, $this->storedStep($factor));

        self::assertTrue($factor->storeAcceptedStep(self::STEP + 1));
        self::assertSame(self::STEP + 1, $factor->getLastAcceptedStep());
        self::assertSame(self::STEP + 1, $this->storedStep($factor));
    }

    /**
     * The row is left as it was.
     *
     * @return void
     */
    public function testAStoredFactorRefusesTheSameOrAnEarlierStep(): void
    {
        $factor = $this->storedFactor();

        self::assertTrue($factor->storeAcceptedStep(self::STEP));
        self::assertFalse($factor->storeAcceptedStep(self::STEP));
        self::assertFalse($factor->storeAcceptedStep(self::STEP - 1));
        self::assertSame(self::STEP, $factor->getLastAcceptedStep());
        self::assertSame(self::STEP, $this->storedStep($factor));
    }

    /**
     * The row as stored decides, not the copy.
     *
     * @return void
     */
    public function testAStaleCopyCannotRecordAStepAnotherCopyRecorded(): void
    {
        $first  = $this->storedFactor();
        $second = Factor::query()->findOrFail($first->id);

        self::assertTrue($first->storeAcceptedStep(self::STEP));

        self::assertNull($second->getLastAcceptedStep());
        self::assertFalse($second->storeAcceptedStep(self::STEP));
        self::assertNull($second->getLastAcceptedStep());
        self::assertSame(self::STEP, $this->storedStep($first));
    }

    /**
     * @return void
     */
    public function testPersistingAfterwardKeepsALaterStepAnotherCopyRecorded(): void
    {
        $first  = $this->storedFactor();
        $second = Factor::query()->findOrFail($first->id);

        self::assertTrue($first->storeAcceptedStep(self::STEP));
        self::assertTrue($second->storeAcceptedStep(self::STEP + 1));

        self::assertFalse($first->isDirty($first->getLastAcceptedStepName()));

        $first->setAttribute('label', 'Phone');
        $first->persist();

        self::assertSame(self::STEP + 1, $this->storedStep($first));
        self::assertSame('Phone', Factor::query()->findOrFail($first->id)->getLabel());
    }

    /**
     * @return void
     */
    public function testOnlyTheFactorsOwnRowIsUpdated(): void
    {
        $factor = $this->storedFactor();
        $other  = $this->storedFactor();

        self::assertTrue($factor->storeAcceptedStep(self::STEP));
        self::assertNull($this->storedStep($other));
    }

    /**
     * A later request can then record the step.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAStepRecordedInsideATransactionRollsBackWithIt(): void
    {
        $factor = $this->storedFactor();

        $thrown = null;

        try {
            FactorStateTransaction::forFactor($factor, static function () use ($factor): void {

                self::assertTrue($factor->storeAcceptedStep(self::STEP));

                throw new MidRotationFailureException('rolled back');
            });
        } catch (MidRotationFailureException $exception) {
            $thrown = $exception;
        }

        self::assertSame('rolled back', $thrown->getMessage());

        self::assertNull($this->storedStep($factor));
        self::assertTrue(Factor::query()->findOrFail($factor->id)->storeAcceptedStep(self::STEP));
        self::assertSame(self::STEP, $this->storedStep($factor));
    }

    /**
     * The step it recorded is stored with it.
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

        self::assertTrue($factor->storeAcceptedStep(self::STEP));
        self::assertFalse($factor->storeAcceptedStep(self::STEP));
        self::assertFalse($factor->storeAcceptedStep(self::STEP - 1));
        self::assertTrue($factor->storeAcceptedStep(self::STEP + 1));

        $factor->persist();

        self::assertSame(self::STEP + 1, $this->storedStep($factor));
    }

    /**
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
     * @param  \SineMacula\Laravel\Mfa\Models\Factor  $factor
     * @return ?int
     *
     * @phpstan-impure
     */
    private function storedStep(Factor $factor): ?int
    {
        $step = DB::table('mfa_factors')->where('id', $factor->id)->value('last_accepted_step');

        if ($step === null) {
            return null;
        }

        self::assertIsNumeric($step);

        return (int) $step;
    }
}
