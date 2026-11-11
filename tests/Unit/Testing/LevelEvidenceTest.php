<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Assurance\Evaluation;
use SineMacula\Laravel\Mfa\Contracts\RequirementCheck;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Testing\LevelEvidence;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Requirements\SignInProofs;
use Tests\TestCase;

/**
 * Tests for `LevelEvidence`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LevelEvidence::class)]
final class LevelEvidenceTest extends TestCase
{
    /**
     * Each level's method, channel and synthetic factor.
     *
     * @return iterable<string, array{\SineMacula\Laravel\Mfa\Enums\AssuranceLevel, string, \SineMacula\Laravel\Mfa\Enums\ChannelKind, string}>
     */
    public static function levels(): iterable
    {
        yield 'AAL1' => [AssuranceLevel::AAL1, 'email', ChannelKind::EMAIL, LevelEvidence::EMAIL_REFERENCE];
        yield 'AAL2' => [AssuranceLevel::AAL2, 'totp', ChannelKind::AUTHENTICATOR_APP, LevelEvidence::TOTP_REFERENCE];
        yield 'AAL3' => [AssuranceLevel::AAL3, 'passkey', ChannelKind::PASSKEY, LevelEvidence::PASSKEY_REFERENCE];
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Enums\AssuranceLevel  $level
     * @param  string  $method
     * @param  \SineMacula\Laravel\Mfa\Enums\ChannelKind  $channel
     * @param  string  $reference
     * @return void
     */
    #[DataProvider('levels')]
    public function testEachLevelHasItsFurtherProof(AssuranceLevel $level, string $method, ChannelKind $channel, string $reference): void
    {
        $proof = LevelEvidence::furtherProof($level, CarbonImmutable::now(), self::binding(), 3);

        self::assertSame(ProofKind::ADDITIONAL_FACTOR, $proof->kind);
        self::assertSame($method, $proof->method);
        self::assertSame($channel, $proof->channel?->kind);
        self::assertSame($reference, $proof->reference);
        self::assertSame($reference, LevelEvidence::syntheticReference($level));
        self::assertSame(3, $proof->generation);
        self::assertSame($level === AssuranceLevel::AAL3 ? true : null, $proof->properties->phishingResistance);
    }

    /**
     * The levels the default combination policy can reach; AAL3 needs a custom
     * one.
     *
     * @return iterable<string, array{\SineMacula\Laravel\Mfa\Enums\AssuranceLevel}>
     */
    public static function reachableLevels(): iterable
    {
        foreach ([AssuranceLevel::AAL1, AssuranceLevel::AAL2] as $level) {
            yield $level->value => [$level];
        }
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Enums\AssuranceLevel  $level
     * @return void
     */
    #[DataProvider('reachableLevels')]
    public function testEachLevelReachesItselfAfterAPassword(AssuranceLevel $level): void
    {
        $proofs = $this->afterAPassword($level);

        LevelEvidence::assertReached($level, $this->check(Requirement::none()->withAdditionalVerification()->withMinimumLevel($level), ...$proofs));

        $this->addToAssertionCount(1);
    }

    /**
     * The factor given is the proof's, and the TOTP channel's; the email and
     * passkey channels keep their synthetic address and credential.
     *
     * @return void
     */
    public function testAGivenFactorIsNamed(): void
    {
        $at = CarbonImmutable::now();

        $totp    = LevelEvidence::furtherProof(AssuranceLevel::AAL2, $at, self::binding(), 0, 'factor-1');
        $email   = LevelEvidence::furtherProof(AssuranceLevel::AAL1, $at, self::binding(), 0, 'factor-1');
        $passkey = LevelEvidence::furtherProof(AssuranceLevel::AAL3, $at, self::binding(), 0, 'factor-1');

        self::assertSame(['factor-1', 'factor-1'], [$totp->reference, $totp->channel?->reference()]);
        self::assertSame(['factor-1', 'verified@example.test'], [$email->reference, $email->channel?->reference()]);
        self::assertSame(['factor-1', LevelEvidence::PASSKEY_REFERENCE], [$passkey->reference, $passkey->channel?->reference()]);
    }

    /**
     * @return void
     */
    public function testTheUnclassifiedLevelHasNoProof(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('An identity cannot be verified at the unclassified level: it supports no level.');

        LevelEvidence::furtherProof(AssuranceLevel::UNCLASSIFIED, CarbonImmutable::now(), self::binding(), 0, 'factor-1');
    }

    /**
     * @return void
     */
    public function testTheUnclassifiedLevelHasNoFactor(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        LevelEvidence::syntheticReference(AssuranceLevel::UNCLASSIFIED);
    }

    /**
     * A password alone meets no requirement's additional verification.
     *
     * @return void
     */
    public function testAnEvaluationWithoutAdditionalVerificationIsRefused(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('Requested aal1 with additional verification; reached aal1; unmet: none.');

        LevelEvidence::assertReached(AssuranceLevel::AAL1, $this->check(Requirement::none(), SignInProofs::of($this->person())->password()));
    }

    /**
     * @return void
     */
    public function testAnotherLevelIsRefused(): void
    {
        $proofs = $this->afterAPassword(AssuranceLevel::AAL2);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('Requested aal1 with additional verification; reached aal2; unmet: none.');

        LevelEvidence::assertReached(AssuranceLevel::AAL1, $this->check(Requirement::none()->withAdditionalVerification(), ...$proofs));
    }

    /**
     * @return void
     */
    public function testAnUnmetRequirementIsRefused(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('unmet: additional_verification.');

        LevelEvidence::assertReached(AssuranceLevel::AAL1, $this->check(Requirement::none()->withAdditionalVerification(), SignInProofs::of($this->person())->password()));
    }

    /**
     * The level reached is not enough when the requirement asks more.
     *
     * @return void
     */
    public function testALevelReachedShortOfTheRequirementIsRefused(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('Requested aal2 with additional verification; reached aal2; unmet: phishing_resistance.');

        LevelEvidence::assertReached(AssuranceLevel::AAL2, $this->check(Requirement::none()->withPhishingResistance(), ...$this->afterAPassword(AssuranceLevel::AAL2)));
    }

    /**
     * A password, then the level's further proof.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\AssuranceLevel  $level
     * @return list<\SineMacula\Laravel\Mfa\Proofs\Proof>
     */
    private function afterAPassword(AssuranceLevel $level): array
    {
        $password = SignInProofs::of($this->person())->password();

        return [$password, LevelEvidence::furtherProof($level, CarbonImmutable::now(), $this->personBinding(), 0)];
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  ...$proofs
     * @return \SineMacula\Laravel\Mfa\Assurance\Evaluation
     */
    private function check(Requirement $requirement, Proof ...$proofs): Evaluation
    {
        return $this->container()->make(RequirementCheck::class)->check($requirement, ...$proofs);
    }

    /**
     * @return \Tests\Fixtures\Identities\TestUser
     */
    private function person(): TestUser
    {
        /** @var \Tests\Fixtures\Identities\TestUser */
        return TestUser::query()->firstOrCreate(['email' => 'evidence@example.test']);
    }

    /**
     * The person's sign-in, as `SignInProofs` binds its proofs.
     *
     * @return \SineMacula\Laravel\Mfa\Proofs\ProofBinding
     */
    private function personBinding(): ProofBinding
    {
        $proofs = SignInProofs::of($this->person());

        return new ProofBinding($proofs->identityType, $proofs->identityKey, $proofs->application, $proofs->sessionId, Purpose::SIGN_IN);
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Proofs\ProofBinding
     */
    private static function binding(): ProofBinding
    {
        return new ProofBinding('user', '42', 'web', 'sign-in-1', Purpose::SIGN_IN);
    }
}
