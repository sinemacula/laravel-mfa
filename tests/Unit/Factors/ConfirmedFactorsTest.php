<?php

declare(strict_types = 1);

namespace Tests\Unit\Factors;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Enums\FactorStatus;
use SineMacula\Laravel\Mfa\Factors\ConfirmedFactors;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\Factors\EnumStatusFactor;
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConfirmedFactors::class)]
final class ConfirmedFactorsTest extends TestCase
{
    /**
     * Whatever the model casts the status to.
     *
     * @return void
     */
    public function testAFactorIsConfirmedByItsStoredStatus(): void
    {
        self::assertTrue(ConfirmedFactors::isConfirmed($this->factor(FactorStatus::CONFIRMED->value)));
        self::assertTrue(ConfirmedFactors::isConfirmed((new EnumStatusFactor)->setRawAttributes(['status' => FactorStatus::CONFIRMED->value])));
    }

    /**
     * @return void
     */
    public function testAFactorWithAnotherOrNoStatusIsNotConfirmed(): void
    {
        self::assertFalse(ConfirmedFactors::isConfirmed($this->factor(FactorStatus::PENDING->value)));
        self::assertFalse(ConfirmedFactors::isConfirmed($this->factor('CONFIRMED')));
        self::assertFalse(ConfirmedFactors::isConfirmed(new Factor));
    }

    /**
     * @return void
     */
    public function testOneConfirmedFactorIsEnoughAmongOthers(): void
    {
        self::assertTrue(ConfirmedFactors::isAmong([$this->factor(FactorStatus::PENDING->value), $this->factor(FactorStatus::CONFIRMED->value)]));
        self::assertFalse(ConfirmedFactors::isAmong([$this->factor(FactorStatus::PENDING->value)]));
        self::assertFalse(ConfirmedFactors::isAmong([]));
    }

    /**
     * Another identity's confirmed factor is not.
     *
     * @return void
     */
    public function testAnIdentityHoldsAConfirmedFactorOfItsOwn(): void
    {
        $person = $this->person('held@example.test');
        $other  = $this->person('other@example.test');

        $this->store($person, FactorStatus::PENDING);
        $this->store($other, FactorStatus::CONFIRMED);

        self::assertFalse(ConfirmedFactors::isHeldBy($person, config()));

        $this->store($person, FactorStatus::CONFIRMED);

        self::assertTrue(ConfirmedFactors::isHeldBy($person, config()));
    }

    /**
     * @param  string  $status
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function factor(string $status): Factor
    {
        return (new Factor)->setRawAttributes(['status' => $status]);
    }

    /**
     * @param  string  $email
     * @return \Tests\Fixtures\Identities\TestUser
     */
    private function person(string $email): TestUser
    {
        return TestUser::query()->create(['email' => $email]);
    }

    /**
     * @param  \Tests\Fixtures\Identities\TestUser  $person
     * @param  \SineMacula\Laravel\Mfa\Enums\FactorStatus  $status
     * @return void
     */
    private function store(TestUser $person, FactorStatus $status): void
    {
        Factor::query()->create([
            'authenticatable_type' => $person->getMorphClass(),
            'authenticatable_id'   => (string) $person->id,
            'type'                 => 'totp',
            'status'               => $status->value,
        ]);
    }
}
