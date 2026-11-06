<?php

declare(strict_types = 1);

namespace Tests\Feature\Factors;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\ActiveStateResolver;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Events\FactorRenamed;
use SineMacula\Laravel\Mfa\Events\PreferredFactorChanged;
use SineMacula\Laravel\Mfa\Factors\FactorChange;
use SineMacula\Laravel\Mfa\Factors\FactorLabel;
use SineMacula\Laravel\Mfa\Factors\FactorService;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Context\InvertedActiveState;
use Tests\Fixtures\Enrollment\Concerns\ArrangesEnrollment;
use Tests\Fixtures\Factors\IntegerKeyedFactor;
use Tests\Fixtures\Identities\NonEloquentIdentity;
use Tests\TestCase;

/**
 * A person renames a factor and chooses a preferred one, with no step-up: a
 * label is what the application it was enrolled through shows, and the
 * preferred factor is the identity's choice across applications.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FactorService::class)]
#[CoversClass(FactorChange::class)]
#[CoversClass(FactorLabel::class)]
final class RenameAndPreferredFactorServiceTest extends TestCase
{
    use ArrangesEnrollment;

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
     * A rename trims the label, needs no step-up and reports the old label.
     *
     * @return void
     */
    public function testARenameIsMade(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->totpFactor($user, ['application' => self::APPLICATION, 'label' => 'Old']);

        $change = $this->mfa()->renameFactor(Callers::current(), $factor->id, '  New  ');

        self::assertTrue($change->wasMade());
        self::assertNull($change->reason);
        self::assertSame('New', $change->factor?->label);
        self::assertSame('New', $factor->refresh()->getLabel());
        self::assertSame(['FactorRenamed'], $this->reportedNames());
        self::assertInstanceOf(FactorRenamed::class, $this->reported[0]);
        self::assertSame('Old', $this->reported[0]->previousLabel);
        self::assertSame(self::APPLICATION, $this->reported[0]->context()['application']);
    }

    /**
     * A blank label is none, and one too long is refused.
     *
     * @return void
     */
    public function testALabelIsNormalized(): void
    {
        $factor = $this->totpFactor($this->signedInPerson(), ['application' => self::APPLICATION, 'label' => 'Old']);

        self::assertNull($this->mfa()->renameFactor(Callers::current(), $factor->id, '   ')->factor?->label);
        self::assertNull($factor->refresh()->getLabel());

        $this->expectException(\InvalidArgumentException::class);

        $this->mfa()->renameFactor(Callers::current(), $factor->id, str_repeat('a', 256));
    }

    /**
     * Only a factor of the person's, enrolled through this application, is
     * renamed; another is `not_found`, reporting nothing.
     *
     * @return void
     */
    public function testARenameIsScopedToTheEnrollingApplication(): void
    {
        $user   = $this->signedInPerson();
        $there  = $this->totpFactor($user, ['application' => 'admin', 'label' => 'There']);
        $theirs = $this->totpFactor($this->person('other@example.test'), ['application' => self::APPLICATION]);

        foreach ([$there->id, $theirs->id, 'unknown', ['not', 'an', 'id'], null] as $id) {
            self::assertSame(FailureReason::NOT_FOUND, $this->mfa()->renameFactor(Callers::current(), $id, 'New')->reason);
        }

        self::assertSame('There', $there->refresh()->getLabel());
        self::assertSame([], $this->reported);
    }

    /**
     * An application's own model may key its factors by integer: such an id is
     * matched as a string, and finds only the factor it names.
     *
     * @return void
     */
    public function testAnIntegerIdIsMatchedAsAString(): void
    {
        config()->set('mfa.factor.model', IntegerKeyedFactor::class);
        config()->set('mfa.factor.table', 'test_integer_keyed_factors');

        $user = $this->signedInPerson();

        $factor = IntegerKeyedFactor::query()->forceCreate([
            'authenticatable_type' => $user->getMorphClass(),
            'authenticatable_id'   => (string) $user->id,
            'type'                 => 'totp',
            'status'               => 'confirmed',
            'application'          => self::APPLICATION,
        ]);

        $id = $factor->getKey();

        self::assertIsInt($id);

        self::assertSame(FailureReason::NOT_FOUND, $this->mfa()->renameFactor(Callers::current(), $id + 1, 'New')->reason);
        self::assertSame(FailureReason::NOT_FOUND, $this->mfa()->setPreferredFactor(Callers::current(), $id + 1)->reason);

        self::assertSame('New', $this->mfa()->renameFactor(Callers::current(), $id, 'New')->factor?->label);
        self::assertTrue($this->mfa()->setPreferredFactor(Callers::current(), $id)->factor?->preferred);
    }

    /**
     * A preference clears the flag across applications, needs no step-up and
     * reports what held it before.
     *
     * @return void
     */
    public function testAPreferenceMovesTheFlag(): void
    {
        $user  = $this->signedInPerson();
        $there = $this->totpFactor($user, ['application' => 'admin', 'preferred' => true]);
        $here  = $this->emailFactor($user, self::ADDRESS, ['application' => self::APPLICATION]);

        $change = $this->mfa()->setPreferredFactor(Callers::current(), $here->id);

        self::assertTrue($change->wasMade());
        self::assertTrue($change->factor?->preferred);
        self::assertTrue($here->refresh()->isPreferred());
        self::assertFalse($there->refresh()->isPreferred());
        self::assertSame(['PreferredFactorChanged'], $this->reportedNames());
        self::assertInstanceOf(PreferredFactorChanged::class, $this->reported[0]);
        self::assertSame($here->id, $this->reported[0]->factor->id);
        self::assertSame($there->id, $this->reported[0]->previous?->id);
        self::assertTrue($this->reported[0]->factor->preferred);
    }

    /**
     * The first preference has nothing before it, and choosing the same one
     * again reports nothing.
     *
     * @return void
     */
    public function testAFirstPreferenceAndARepeatOne(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->totpFactor($user, ['application' => self::APPLICATION]);

        $this->mfa()->setPreferredFactor(Callers::current(), $factor->id);

        self::assertInstanceOf(PreferredFactorChanged::class, $this->reported[0]);
        self::assertNull($this->reported[0]->previous);

        $this->forgetReports();

        $again = $this->mfa()->setPreferredFactor(Callers::current(), $factor->id);

        self::assertTrue($again->factor?->preferred);
        self::assertSame([], $this->reported);
    }

    /**
     * A preference needs a confirmed factor of a type this application enables.
     *
     * @return void
     */
    public function testAPreferenceNeedsAConfirmedFactorOfAnEnabledType(): void
    {
        $user    = $this->signedInPerson();
        $pending = $this->totpFactor($user, ['status' => 'pending']);
        $sms     = $this->factorOf($user, ['type' => 'sms', 'destination' => '+447700900123']);

        self::assertSame(FailureReason::NOT_FOUND, $this->mfa()->setPreferredFactor(Callers::current(), $pending->id)->reason);
        self::assertSame(FailureReason::TYPE_NOT_ENABLED, $this->mfa()->setPreferredFactor(Callers::current(), $sms->id)->reason);
        self::assertSame(FailureReason::NOT_FOUND, $this->mfa()->setPreferredFactor(Callers::current(), 'unknown')->reason);
        self::assertSame(0, Factor::query()->where('preferred', true)->count());
        self::assertSame([], $this->reported);
    }

    /**
     * A pending session is served nothing, whatever it allows, and an inactive
     * identity is refused.
     *
     * @return void
     */
    public function testOnlyAnActiveSessionOfAnActivePersonIsServed(): void
    {
        self::assertSame(FailureReason::NOT_FOUND, $this->mfa()->renameFactor(Callers::current(), 'any', 'New')->reason);

        $user = $this->person();

        $this->pendingSession($user, null, [PendingAction::LIST_FACTORS, PendingAction::VERIFY, PendingAction::START_BOOTSTRAP_ENROLLMENT]);

        self::assertSame(FailureReason::NOT_FOUND, $this->mfa()->renameFactor(Callers::current(), 'any', 'New')->reason);
        self::assertSame(FailureReason::NOT_FOUND, $this->mfa()->setPreferredFactor(Callers::current(), 'any')->reason);

        $this->noPendingSession();
        $this->actingAs(new NonEloquentIdentity(active: false));

        self::assertSame(FailureReason::IDENTITY_INACTIVE, $this->mfa()->renameFactor(Callers::current(), 'any', 'New')->reason);
        self::assertSame(FailureReason::IDENTITY_INACTIVE, $this->mfa()->setPreferredFactor(Callers::current(), 'any')->reason);
    }

    /**
     * The bound active state resolver, not the identity, decides who is served:
     * a person it finds inactive is refused and their factor left as it was,
     * and an identity it finds active is served.
     *
     * @return void
     */
    public function testTheBoundActiveStateResolverDecidesWhoIsServed(): void
    {
        $this->container()->instance(ActiveStateResolver::class, new InvertedActiveState);

        $user   = $this->signedInPerson();
        $factor = $this->totpFactor($user, ['application' => self::APPLICATION, 'label' => 'Old']);

        self::assertSame(FailureReason::IDENTITY_INACTIVE, $this->mfa()->renameFactor(Callers::current(), $factor->id, 'New')->reason);
        self::assertSame(FailureReason::IDENTITY_INACTIVE, $this->mfa()->setPreferredFactor(Callers::current(), $factor->id)->reason);
        self::assertSame('Old', $factor->refresh()->getLabel());
        self::assertSame(0, Factor::query()->where('preferred', true)->count());
        self::assertSame([], $this->reported);

        $this->actingAs(new NonEloquentIdentity(active: false));

        self::assertSame(FailureReason::NOT_FOUND, $this->mfa()->renameFactor(Callers::current(), 'any', 'New')->reason);
        self::assertSame(FailureReason::NOT_FOUND, $this->mfa()->setPreferredFactor(Callers::current(), 'any')->reason);
    }
}
