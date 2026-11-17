<?php

declare(strict_types = 1);

namespace Tests\Unit\Proofs;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Proofs\CountingProofs;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Requirements\SignInProofs;
use Tests\TestCase;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CountingProofs::class)]
final class CountingProofsTest extends TestCase
{
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
     * Not another identity's, application's or session's.
     *
     * @return void
     */
    public function testCountsOnlyTheSignInsOwnProofs(): void
    {
        $proofs = SignInProofs::of($this->person());
        $own    = $proofs->password();

        $counting = CountingProofs::of($this->person(), SignInProofs::APPLICATION, SignInProofs::SESSION, [
            $proofs->ofIdentity('someone-else')->password(),
            $proofs->onApplication('api')->password(),
            $proofs->inSession('sign-in-2')->password(),
            'kept' => $own,
        ]);

        self::assertSame([$own], $counting);
    }

    /**
     * @return void
     */
    public function testCountsNoProofOfAnotherGeneration(): void
    {
        $person = $this->person();
        $proofs = SignInProofs::of($person);
        $stale  = $proofs->password();

        $generation = VerificationGeneration::advance($person);
        $current    = $proofs->underGeneration($generation)->totp();

        self::assertSame([$current], CountingProofs::of($person, SignInProofs::APPLICATION, SignInProofs::SESSION, [$stale, $current]));
    }

    /**
     * @return void
     */
    public function testCountsNoProofMadeLaterThanNow(): void
    {
        $proofs = SignInProofs::of($this->person());
        $now    = $proofs->password();

        self::assertSame([$now], CountingProofs::of($this->person(), SignInProofs::APPLICATION, SignInProofs::SESSION, [$proofs->totp(-60), $now]));
    }

    /**
     * Proofs made at one instant keep the order given.
     *
     * @return void
     */
    public function testListsTheProofsOldestFirst(): void
    {
        CarbonImmutable::setTestNow('2026-11-01 12:00:00');

        $proofs   = SignInProofs::of($this->person());
        $oldest   = $proofs->password(120);
        $email    = $proofs->email(30);
        $totp     = $proofs->totp(30);
        $youngest = $proofs->totp();

        $counting = CountingProofs::of($this->person(), SignInProofs::APPLICATION, SignInProofs::SESSION, [$youngest, $email, $oldest, $totp]);

        self::assertSame([$oldest, $email, $totp, $youngest], $counting);
    }

    /**
     * @return \Tests\Fixtures\Identities\TestUser
     */
    private function person(): TestUser
    {
        /** @var \Tests\Fixtures\Identities\TestUser */
        return TestUser::query()->firstOrCreate(['email' => 'counting@example.test']);
    }
}
