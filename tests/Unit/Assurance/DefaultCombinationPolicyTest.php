<?php

declare(strict_types = 1);

namespace Tests\Unit\Assurance;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Assurance\Authenticator;
use SineMacula\Laravel\Mfa\Assurance\Channel;
use SineMacula\Laravel\Mfa\Assurance\Combination;
use SineMacula\Laravel\Mfa\Assurance\DefaultCombinationPolicy;
use SineMacula\Laravel\Mfa\Assurance\Evaluation;
use SineMacula\Laravel\Mfa\Assurance\ObservedProperties;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\KeyProtection;
use SineMacula\Laravel\Mfa\Enums\RequirementPart;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use Tests\Fixtures\Assurance\SessionProofs;

/**
 * Tests for `DefaultCombinationPolicy`: which factors may follow which first
 * factors, the classification of every combination of the default table, the
 * `amr` values reported, and the requirement parts met, with their maximum
 * ages.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DefaultCombinationPolicy::class)]
#[CoversClass(Combination::class)]
#[CoversClass(Authenticator::class)]
final class DefaultCombinationPolicyTest extends TestCase
{
    /** @var int The maximum age of a fresh operation, in seconds. */
    private const int FRESH = 900;

    /** @var int The age of a proof made two hours ago, in seconds. */
    private const int TWO_HOURS = 7200;

    /**
     * Fix the time every proof's age is measured from.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        CarbonImmutable::setTestNow(SessionProofs::now());
    }

    /**
     * Release the fixed time.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * Rows of a first factor, a factor's channel, and whether the factor may
     * follow it.
     *
     * @return iterable<string, array{\SineMacula\Laravel\Mfa\Proofs\Proof, \SineMacula\Laravel\Mfa\Assurance\Channel, bool}>
     */
    public static function provideFactorsAfterFirstFactors(): iterable
    {
        yield 'TOTP after a password' => [SessionProofs::password(), new Channel(ChannelKind::AUTHENTICATOR_APP, 'factor-totp'), true];
        yield 'a password channel as a factor' => [SessionProofs::password(), new Channel(ChannelKind::PASSWORD), false];
        yield 'an unknown channel as a factor' => [SessionProofs::password(), Channel::unknown(), false];
        yield 'SMS to the phone signed in with' => [SessionProofs::phoneCode(), new Channel(ChannelKind::SMS, SessionProofs::PHONE), false];
        yield 'SMS to another phone' => [SessionProofs::phoneCode(), new Channel(ChannelKind::SMS, SessionProofs::OTHER_PHONE), true];
        yield 'SMS with no phone named' => [SessionProofs::phoneCode(), new Channel(ChannelKind::SMS), false];
        yield 'SMS after a phone code to no known phone' => [SessionProofs::phoneCode(null), new Channel(ChannelKind::SMS, SessionProofs::OTHER_PHONE), false];
        yield 'email after a phone code' => [SessionProofs::phoneCode(), new Channel(ChannelKind::EMAIL, SessionProofs::EMAIL), true];
        yield 'email to the address signed in with' => [SessionProofs::emailCode(), new Channel(ChannelKind::EMAIL, SessionProofs::EMAIL), false];
        yield 'email to the same address in another case' => [SessionProofs::emailCode(), new Channel(ChannelKind::EMAIL, 'Person@Example.COM'), false];
        yield 'email to the same accented address in another case' => [
            SessionProofs::emailCode('élodie@example.com'),
            new Channel(ChannelKind::EMAIL, 'ÉLODIE@example.com'),
            false,
        ];
        yield 'email to another address' => [SessionProofs::emailCode(), new Channel(ChannelKind::EMAIL, SessionProofs::OTHER_EMAIL), true];
        yield 'SMS after an email code' => [SessionProofs::emailCode(), new Channel(ChannelKind::SMS, SessionProofs::PHONE), true];
        yield 'the passkey signed in with' => [SessionProofs::passkeySignIn(SessionProofs::verified()), new Channel(ChannelKind::PASSKEY, SessionProofs::PASSKEY), false];
        yield 'a passkey whose credential differs only in case' => [
            SessionProofs::passkeySignIn(SessionProofs::verified()),
            new Channel(ChannelKind::PASSKEY, 'Credential-1'),
            true,
        ];
        yield 'another passkey' => [SessionProofs::passkeySignIn(SessionProofs::verified()), new Channel(ChannelKind::PASSKEY, SessionProofs::OTHER_PASSKEY), true];
        yield 'TOTP after an external provider' => [SessionProofs::externalProvider(), new Channel(ChannelKind::AUTHENTICATOR_APP, 'factor-totp'), true];
        yield 'TOTP after an unknown first factor' => [SessionProofs::unknownFirstFactor(), new Channel(ChannelKind::AUTHENTICATOR_APP, 'factor-totp'), false];
        yield 'TOTP after a reauthentication with a password' => [
            SessionProofs::reauthentication(new Channel(ChannelKind::PASSWORD)),
            new Channel(ChannelKind::AUTHENTICATOR_APP, 'factor-totp'),
            true,
        ];
        yield 'TOTP after a reauthentication on an unknown channel' => [
            SessionProofs::reauthentication(Channel::unknown()),
            new Channel(ChannelKind::AUTHENTICATOR_APP, 'factor-totp'),
            false,
        ];
        yield 'SMS after another factor, which is no first factor' => [SessionProofs::totp(), new Channel(ChannelKind::SMS, SessionProofs::OTHER_PHONE), false];
        yield 'TOTP after a recovery code, which is no first factor' => [SessionProofs::recoveryCode(), new Channel(ChannelKind::AUTHENTICATOR_APP, 'factor-totp'), false];
    }

    /**
     * A factor may follow a known first factor unless it shares its channel or
     * cannot carry a factor; a first factor that is unknown, or no first factor
     * at all, accepts nothing.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $firstFactor
     * @param  \SineMacula\Laravel\Mfa\Assurance\Channel  $factor
     * @param  bool  $accepted
     * @return void
     */
    #[DataProvider('provideFactorsAfterFirstFactors')]
    public function testAcceptsAFactorOnlyOnAnIndependentChannel(Proof $firstFactor, Channel $factor, bool $accepted): void
    {
        self::assertSame($accepted, (new DefaultCombinationPolicy)->accepts($firstFactor, $factor));
    }

    /**
     * One row per row of the default classification, then the unknown channel,
     * the same channel and a passkey that did not verify the person: the
     * proofs, then whether the combination is accepted, multifactor,
     * phishing-resistant and restricted, its level and its `amr` values.
     *
     * @return iterable<string, array{list<\SineMacula\Laravel\Mfa\Proofs\Proof>, bool, bool, bool, bool, \SineMacula\Laravel\Mfa\Enums\AssuranceLevel, list<string>}>
     */
    public static function provideCombinations(): iterable
    {
        $verified   = SessionProofs::verified();
        $unverified = SessionProofs::unverified();

        yield 'password, TOTP' => [[SessionProofs::password(), SessionProofs::totp()], true, true, false, false, AssuranceLevel::AAL2, ['pwd', 'otp', 'mfa']];
        yield 'password, passkey' => [
            [SessionProofs::password(), SessionProofs::passkey($unverified)],
            true,
            true,
            true,
            false,
            AssuranceLevel::AAL2,
            ['pwd', 'pop', 'user', 'mfa'],
        ];
        yield 'password, recovery code' => [[SessionProofs::password(), SessionProofs::recoveryCode()], true, true, false, false, AssuranceLevel::AAL2, ['pwd', 'otp', 'mfa']];
        yield 'password, SMS code' => [[SessionProofs::password(), SessionProofs::sms()], true, true, false, true, AssuranceLevel::AAL2, ['pwd', 'sms', 'mfa']];
        yield 'password, email code' => [[SessionProofs::password(), SessionProofs::email()], true, false, false, false, AssuranceLevel::AAL1, ['pwd', 'otp', 'mca']];
        yield 'phone code, TOTP' => [[SessionProofs::phoneCode(), SessionProofs::totp()], true, false, false, true, AssuranceLevel::AAL1, ['sms', 'otp', 'mca']];
        yield 'phone code, recovery code' => [[SessionProofs::phoneCode(), SessionProofs::recoveryCode()], true, false, false, true, AssuranceLevel::AAL1, ['sms', 'otp', 'mca']];
        yield 'phone code, SMS code to a different phone' => [[SessionProofs::phoneCode(), SessionProofs::sms()], true, false, false, true, AssuranceLevel::AAL1, ['sms', 'mca']];
        yield 'phone code, email code' => [[SessionProofs::phoneCode(), SessionProofs::email()], true, false, false, true, AssuranceLevel::AAL1, ['sms', 'otp', 'mca']];
        yield 'phone code, passkey with observed verification' => [
            [SessionProofs::phoneCode(), SessionProofs::passkey($verified)],
            true,
            true,
            true,
            false,
            AssuranceLevel::AAL2,
            ['sms', 'pop', 'user', 'mfa'],
        ];
        yield 'email code, passkey with observed verification' => [
            [SessionProofs::emailCode(), SessionProofs::passkey($verified)],
            true,
            true,
            true,
            false,
            AssuranceLevel::AAL2,
            ['otp', 'pop', 'user', 'mfa'],
        ];
        yield 'email code, TOTP' => [[SessionProofs::emailCode(), SessionProofs::totp()], true, false, false, false, AssuranceLevel::AAL1, ['otp', 'mca']];
        yield 'email code, recovery code' => [[SessionProofs::emailCode(), SessionProofs::recoveryCode()], true, false, false, false, AssuranceLevel::AAL1, ['otp', 'mca']];
        yield 'email code, SMS code' => [
            [SessionProofs::emailCode(), SessionProofs::sms(SessionProofs::PHONE)],
            true,
            false,
            false,
            true,
            AssuranceLevel::AAL1,
            ['otp', 'sms', 'mca'],
        ];
        yield 'phone code, SMS code to the same phone' => [
            [SessionProofs::phoneCode(), SessionProofs::sms(SessionProofs::PHONE)],
            false,
            false,
            false,
            true,
            AssuranceLevel::AAL1,
            ['sms'],
        ];
        yield 'email code, email code to the same address' => [
            [SessionProofs::emailCode(), SessionProofs::email(SessionProofs::EMAIL)],
            false,
            false,
            false,
            false,
            AssuranceLevel::UNCLASSIFIED,
            ['otp'],
        ];
        yield 'passkey with observed verification, nothing more' => [
            [SessionProofs::passkeySignIn($verified)],
            false,
            true,
            true,
            false,
            AssuranceLevel::AAL2,
            ['pop', 'user', 'mfa'],
        ];
        yield 'external provider, TOTP' => [[SessionProofs::externalProvider(), SessionProofs::totp()], true, false, false, false, AssuranceLevel::AAL1, ['otp', 'mca']];
        yield 'external provider, email code' => [
            [SessionProofs::externalProvider(), SessionProofs::email()],
            true,
            false,
            false,
            false,
            AssuranceLevel::UNCLASSIFIED,
            ['otp', 'mca'],
        ];
        yield 'external provider, passkey with observed verification' => [
            [SessionProofs::externalProvider(), SessionProofs::passkey($verified)],
            true,
            true,
            true,
            false,
            AssuranceLevel::AAL2,
            ['pop', 'user', 'mfa'],
        ];
        yield 'unknown first factor, TOTP' => [[SessionProofs::unknownFirstFactor(), SessionProofs::totp()], false, false, false, false, AssuranceLevel::UNCLASSIFIED, []];
        yield 'unknown first factor, passkey with observed verification' => [
            [SessionProofs::unknownFirstFactor(), SessionProofs::passkey($verified)],
            false,
            false,
            false,
            false,
            AssuranceLevel::UNCLASSIFIED,
            [],
        ];
        yield 'no first factor, TOTP' => [[SessionProofs::totp()], false, false, false, false, AssuranceLevel::UNCLASSIFIED, []];
        yield 'passkey signed in with, then as a factor' => [
            [SessionProofs::passkeySignIn($unverified), SessionProofs::passkey($unverified, SessionProofs::PASSKEY)],
            false,
            false,
            true,
            false,
            AssuranceLevel::AAL1,
            ['pop', 'user'],
        ];
        yield 'phone code, passkey without observed verification' => [
            [SessionProofs::phoneCode(), SessionProofs::passkey($unverified)],
            true,
            false,
            true,
            true,
            AssuranceLevel::AAL1,
            ['sms', 'pop', 'user', 'mca'],
        ];
        yield 'phone code, passkey observed not to verify' => [
            [SessionProofs::phoneCode(), SessionProofs::passkey(SessionProofs::unverified(false))],
            true,
            false,
            true,
            true,
            AssuranceLevel::AAL1,
            ['sms', 'pop', 'user', 'mca'],
        ];
        yield 'passkey without observed verification, nothing more' => [
            [SessionProofs::passkeySignIn($unverified)],
            false,
            false,
            true,
            false,
            AssuranceLevel::AAL1,
            ['pop', 'user'],
        ];
        yield 'password, nothing more' => [[SessionProofs::password()], false, false, false, false, AssuranceLevel::AAL1, ['pwd']];
        yield 'email code, nothing more' => [[SessionProofs::emailCode()], false, false, false, false, AssuranceLevel::UNCLASSIFIED, ['otp']];
    }

    /**
     * Each combination is accepted, multifactor and levelled as the default
     * classification says, from what its proofs observed.
     *
     * @param  list<\SineMacula\Laravel\Mfa\Proofs\Proof>  $proofs
     * @param  bool  $accepted
     * @param  bool  $multifactor
     * @param  bool  $phishingResistant
     * @param  bool  $restricted
     * @param  \SineMacula\Laravel\Mfa\Enums\AssuranceLevel  $level
     * @param  list<string>  $amr
     * @return void
     */
    #[DataProvider('provideCombinations')]
    public function testClassifiesTheCombination(
        array $proofs,
        bool $accepted,
        bool $multifactor,
        bool $phishingResistant,
        bool $restricted,
        AssuranceLevel $level,
        array $amr,
    ): void {
        $evaluation = $this->evaluate(Requirement::none(), ...$proofs);

        self::assertSame([
            'accepted'           => $accepted,
            'multifactor'        => $multifactor,
            'level'              => $level->value,
            'phishing_resistant' => $phishingResistant,
            'restricted'         => $restricted,
            'amr'                => $amr,
            'met'                => [],
            'unmet'              => [],
        ], $evaluation->toArray());
    }

    /**
     * The proofs are classified the same in any order, and the first factor's
     * `amr` values come first.
     *
     * @return void
     */
    public function testTheOrderOfTheProofsDoesNotMatter(): void
    {
        $evaluation = $this->evaluate(Requirement::none(), SessionProofs::totp(), SessionProofs::password());

        self::assertTrue($evaluation->accepted);
        self::assertTrue($evaluation->multifactor);
        self::assertSame(AssuranceLevel::AAL2, $evaluation->level);
        self::assertSame(['pwd', 'otp', 'mfa'], $evaluation->amr);
    }

    /**
     * A combination is restricted only when every way of reaching its level
     * relies on a restricted authenticator.
     *
     * @return void
     */
    public function testANonRestrictedProofAtTheSameLevelLiftsTheRestriction(): void
    {
        $evaluation = $this->evaluate(Requirement::none(), SessionProofs::password(), SessionProofs::sms(), SessionProofs::totp());

        self::assertSame(AssuranceLevel::AAL2, $evaluation->level);
        self::assertFalse($evaluation->restricted);
        self::assertSame(['pwd', 'sms', 'otp', 'mfa'], $evaluation->amr);
    }

    /**
     * The level never reaches AAL3, even for a passkey observed to verify the
     * person on a hardware key, and the key's protection is reported only as
     * observed.
     *
     * @return void
     */
    public function testNeverReportsAal3(): void
    {
        $requirement = Requirement::none()->withMinimumLevel(AssuranceLevel::AAL3);
        $hardware    = $this->evaluate($requirement, SessionProofs::passkeySignIn(SessionProofs::verified(KeyProtection::HARDWARE)));
        $software    = $this->evaluate($requirement, SessionProofs::passkeySignIn(SessionProofs::verified(KeyProtection::SOFTWARE)));

        self::assertSame(AssuranceLevel::AAL2, $hardware->level);
        self::assertSame([RequirementPart::MINIMUM_LEVEL], $hardware->unmet);
        self::assertSame(['pop', 'user', 'hwk', 'mfa'], $hardware->amr);
        self::assertSame(['pop', 'user', 'swk', 'mfa'], $software->amr);
    }

    /**
     * A first factor's own `amr` values report user presence only when it was
     * observed, and a property observed false reports nothing.
     *
     * @return void
     */
    public function testReportsOnlyWhatWasObserved(): void
    {
        $absent = new ObservedProperties(userPresence: false, phishingResistance: false);

        $evaluation = $this->evaluate(Requirement::none(), SessionProofs::password(), SessionProofs::passkey($absent));

        self::assertFalse($evaluation->phishingResistant);
        self::assertSame(['pwd', 'pop', 'mfa'], $evaluation->amr);
    }

    /**
     * A multi-factor first factor meets an additional verification and
     * multifactor authentication on its own, and its level and phishing
     * resistance are evaluated like any proof's.
     *
     * @return void
     */
    public function testAMultiFactorFirstFactorMeetsTheRequirementOnItsOwn(): void
    {
        $requirement = Requirement::none()
            ->withAdditionalVerification()
            ->withMultifactor()
            ->withMinimumLevel(AssuranceLevel::AAL2)
            ->withPhishingResistance();

        $evaluation = $this->evaluate($requirement, SessionProofs::passkeySignIn(SessionProofs::verified()));

        self::assertFalse($evaluation->accepted);
        self::assertSame($requirement->parts(), $evaluation->met);
        self::assertTrue($evaluation->meetsRequirement());
    }

    /**
     * An old multi-factor first factor does not meet a requirement for a fresh
     * proof, while what it established stays reported; a fresh further proof
     * then meets it.
     *
     * @return void
     */
    public function testAnOldMultiFactorFirstFactorIsNotFreshForAnOperation(): void
    {
        $requirement = Requirement::none()->withAdditionalVerification(self::FRESH)->withMultifactor(self::FRESH)->withMinimumLevel(AssuranceLevel::AAL2, self::FRESH);
        $firstFactor = SessionProofs::passkeySignIn(SessionProofs::verified(), self::TWO_HOURS);

        $old   = $this->evaluate($requirement, $firstFactor);
        $fresh = $this->evaluate($requirement, $firstFactor, SessionProofs::totp());

        self::assertTrue($old->multifactor);
        self::assertSame(AssuranceLevel::AAL2, $old->level);
        self::assertSame([], $old->met);
        self::assertSame($requirement->parts(), $old->unmet);
        self::assertSame($requirement->parts(), $fresh->met);
    }

    /**
     * A fresh further proof refreshes the combination it completes after an old
     * first factor.
     *
     * @return void
     */
    public function testAFreshFurtherProofMeetsAFreshRequirement(): void
    {
        $requirement = Requirement::none()->withMultifactor(self::FRESH);

        $evaluation = $this->evaluate($requirement, SessionProofs::password(self::TWO_HOURS), SessionProofs::totp());

        self::assertSame([RequirementPart::MULTIFACTOR], $evaluation->met);
    }

    /**
     * A fresh reauthentication with the first factor meets a fresh level it
     * reaches on its own, but never stands in for an additional factor made
     * long ago.
     *
     * @return void
     */
    public function testAFreshFirstFactorNeverStandsInForAnAdditionalFactor(): void
    {
        $requirement = Requirement::none()->withAdditionalVerification(self::FRESH)->withMinimumLevel(AssuranceLevel::AAL1, self::FRESH);

        $evaluation = $this->evaluate(
            $requirement,
            SessionProofs::password(self::TWO_HOURS),
            SessionProofs::totp(self::TWO_HOURS),
            SessionProofs::reauthentication(new Channel(ChannelKind::PASSWORD)),
        );

        self::assertTrue($evaluation->accepted);
        self::assertSame([RequirementPart::MINIMUM_LEVEL], $evaluation->met);
        self::assertSame([RequirementPart::ADDITIONAL_VERIFICATION], $evaluation->unmet);
    }

    /**
     * A reauthentication on an unknown channel establishes nothing, so it does
     * not refresh the first factor.
     *
     * @return void
     */
    public function testAReauthenticationOnAnUnknownChannelCountsForNothing(): void
    {
        $requirement = Requirement::none()->withMinimumLevel(AssuranceLevel::AAL1, self::FRESH);

        $evaluation = $this->evaluate($requirement, SessionProofs::password(self::TWO_HOURS), SessionProofs::reauthentication(Channel::unknown()));

        self::assertSame(AssuranceLevel::AAL1, $evaluation->level);
        self::assertSame([RequirementPart::MINIMUM_LEVEL], $evaluation->unmet);
        self::assertSame(['pwd'], $evaluation->amr);
    }

    /**
     * Rows of a proof's age and whether it meets a part with a maximum age of
     * fifteen minutes.
     *
     * @return iterable<string, array{int, bool}>
     */
    public static function provideAges(): iterable
    {
        yield 'made now' => [0, true];
        yield 'made exactly at the maximum age' => [self::FRESH, true];
        yield 'made a second past the maximum age' => [self::FRESH + 1, false];
        yield 'made a second in the future' => [-1, false];
    }

    /**
     * A part with a maximum age is met by a proof no older than it, and never
     * by one made in the future.
     *
     * @param  int  $secondsAgo
     * @param  bool  $met
     * @return void
     */
    #[DataProvider('provideAges')]
    public function testAMaximumAgeIsInclusive(int $secondsAgo, bool $met): void
    {
        $requirement = Requirement::none()->withMultifactor(self::FRESH);

        $evaluation = $this->evaluate($requirement, SessionProofs::password(self::TWO_HOURS), SessionProofs::totp($secondsAgo));

        self::assertSame($met, $evaluation->meetsRequirement());
    }

    /**
     * Rows of a session's proofs, a requirement, and the parts it meets and
     * does not meet.
     *
     * @return iterable<string, array{
     *     list<\SineMacula\Laravel\Mfa\Proofs\Proof>,
     *     \SineMacula\Laravel\Mfa\Requirements\Requirement,
     *     list<\SineMacula\Laravel\Mfa\Enums\RequirementPart>,
     *     list<\SineMacula\Laravel\Mfa\Enums\RequirementPart>,
     * }>
     */
    public static function provideRequirements(): iterable
    {
        $everything = Requirement::none()->withAdditionalVerification()->withMultifactor()->withMinimumLevel(AssuranceLevel::AAL2)->withPhishingResistance();
        $all        = [RequirementPart::ADDITIONAL_VERIFICATION, RequirementPart::MULTIFACTOR, RequirementPart::MINIMUM_LEVEL, RequirementPart::PHISHING_RESISTANCE];

        yield 'password and a passkey meet everything' => [[SessionProofs::password(), SessionProofs::passkey(SessionProofs::unverified())], $everything, $all, []];
        yield 'password and TOTP are not phishing-resistant' => [
            [SessionProofs::password(), SessionProofs::totp()],
            $everything,
            [RequirementPart::ADDITIONAL_VERIFICATION, RequirementPart::MULTIFACTOR, RequirementPart::MINIMUM_LEVEL],
            [RequirementPart::PHISHING_RESISTANCE],
        ];
        yield 'password and an email code are an additional verification only' => [
            [SessionProofs::password(), SessionProofs::email()],
            $everything,
            [RequirementPart::ADDITIONAL_VERIFICATION],
            [RequirementPart::MULTIFACTOR, RequirementPart::MINIMUM_LEVEL, RequirementPart::PHISHING_RESISTANCE],
        ];
        yield 'a phone code and TOTP reach AAL1' => [
            [SessionProofs::phoneCode(), SessionProofs::totp()],
            Requirement::none()->withMinimumLevel(AssuranceLevel::AAL1),
            [RequirementPart::MINIMUM_LEVEL],
            [],
        ];
        yield 'a phone code and TOTP fall short of AAL2' => [
            [SessionProofs::phoneCode(), SessionProofs::totp()],
            Requirement::none()->withMinimumLevel(AssuranceLevel::AAL2),
            [],
            [RequirementPart::MINIMUM_LEVEL],
        ];
        yield 'a password alone is no additional verification' => [
            [SessionProofs::password()],
            Requirement::none()->withAdditionalVerification()->withMinimumLevel(AssuranceLevel::AAL1),
            [RequirementPart::MINIMUM_LEVEL],
            [RequirementPart::ADDITIONAL_VERIFICATION],
        ];
        yield 'an email code alone meets no level' => [
            [SessionProofs::emailCode()],
            Requirement::none()->withMinimumLevel(AssuranceLevel::AAL1),
            [],
            [RequirementPart::MINIMUM_LEVEL],
        ];
        yield 'an unknown first factor meets nothing' => [[SessionProofs::unknownFirstFactor(), SessionProofs::passkey(SessionProofs::verified())], $everything, [], $all];
        yield 'an unknown first factor is not refreshed by a reauthentication' => [
            [SessionProofs::unknownFirstFactor(), SessionProofs::reauthentication(new Channel(ChannelKind::PASSWORD))],
            Requirement::none()->withMinimumLevel(AssuranceLevel::AAL1),
            [],
            [RequirementPart::MINIMUM_LEVEL],
        ];
        yield 'an unknown first factor is not lifted by a recovery code' => [
            [SessionProofs::unknownFirstFactor(), SessionProofs::recoveryCode()],
            $everything,
            [],
            $all,
        ];
        yield 'two first factors meet nothing' => [
            [SessionProofs::password(), SessionProofs::passkeySignIn(SessionProofs::verified()), SessionProofs::totp()],
            $everything,
            [],
            $all,
        ];
    }

    /**
     * Each part of a requirement is met or not on its own, from what the
     * combinations provide.
     *
     * @param  list<\SineMacula\Laravel\Mfa\Proofs\Proof>  $proofs
     * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @param  list<\SineMacula\Laravel\Mfa\Enums\RequirementPart>  $met
     * @param  list<\SineMacula\Laravel\Mfa\Enums\RequirementPart>  $unmet
     * @return void
     */
    #[DataProvider('provideRequirements')]
    public function testJudgesEachPartOfTheRequirement(array $proofs, Requirement $requirement, array $met, array $unmet): void
    {
        $evaluation = $this->evaluate($requirement, ...$proofs);

        self::assertSame($met, $evaluation->met);
        self::assertSame($unmet, $evaluation->unmet);
    }

    /**
     * Rows of a further proof bound to another identity or application than the
     * first factor.
     *
     * @return iterable<string, array{\SineMacula\Laravel\Mfa\Proofs\Proof}>
     */
    public static function provideForeignProofs(): iterable
    {
        yield 'another identity type' => [SessionProofs::totp(identityType: 'admin')];
        yield 'another identity key' => [SessionProofs::totp(identityKey: '43')];
        yield 'another application' => [SessionProofs::totp(application: 'mobile')];
    }

    /**
     * A further proof bound to another identity or application than the first
     * factor counts for nothing.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $foreign
     * @return void
     */
    #[DataProvider('provideForeignProofs')]
    public function testAProofBoundElsewhereCountsForNothing(Proof $foreign): void
    {
        $evaluation = $this->evaluate(Requirement::none()->withAdditionalVerification(), SessionProofs::password(), $foreign);

        self::assertFalse($evaluation->accepted);
        self::assertSame(AssuranceLevel::AAL1, $evaluation->level);
        self::assertSame(['pwd'], $evaluation->amr);
        self::assertSame([RequirementPart::ADDITIONAL_VERIFICATION], $evaluation->unmet);
    }

    /**
     * A proof that counts for nothing does not stop the proofs after it from
     * counting.
     *
     * @return void
     */
    public function testAProofBoundElsewhereDoesNotHideTheProofsAfterIt(): void
    {
        $evaluation = $this->evaluate(
            Requirement::none()->withAdditionalVerification(),
            SessionProofs::password(),
            SessionProofs::totp(application: 'mobile'),
            SessionProofs::totp(),
        );

        self::assertTrue($evaluation->accepted);
        self::assertSame([RequirementPart::ADDITIONAL_VERIFICATION], $evaluation->met);
    }

    /**
     * Evaluate the proofs with the default policy.
     *
     * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  ...$proofs
     * @return \SineMacula\Laravel\Mfa\Assurance\Evaluation
     */
    private function evaluate(Requirement $requirement, Proof ...$proofs): Evaluation
    {
        return (new DefaultCombinationPolicy)->evaluate($requirement, ...$proofs);
    }
}
