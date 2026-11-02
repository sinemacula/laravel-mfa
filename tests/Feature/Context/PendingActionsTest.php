<?php

declare(strict_types = 1);

namespace Tests\Feature\Context;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Context\CallerContextResolver;
use SineMacula\Laravel\Mfa\Context\PendingContext;
use SineMacula\Laravel\Mfa\Contracts\Factor as FactorContract;
use SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Factors\FactorService;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Models\RecoveryCode;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Testing\FakeEmailSender;
use SineMacula\Laravel\Mfa\Verification\VerificationService;
use Tests\Fixtures\Context\FixedPendingSessionResolver;
use Tests\Fixtures\Exceptions\InvalidPendingCredentialException;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Requirements\SignInProofs;
use Tests\TestCase;

/**
 * Every helper that returns summaries, sends a code or reveals a secret serves
 * a pending session only the action it needs, as the pending session's own
 * identity, and never the guard's user in its place.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CallerContextResolver::class)]
#[CoversClass(FactorService::class)]
#[CoversClass(VerificationService::class)]
#[CoversClass(MfaManager::class)]
final class PendingActionsTest extends TestCase
{
    /** @var \Tests\Fixtures\Identities\TestUser The person the guard signed in. */
    private TestUser $guarded;

    /** @var \Tests\Fixtures\Identities\TestUser The person signing in on the pending session. */
    private TestUser $pending;

    /** @var \SineMacula\Laravel\Mfa\Models\Factor The pending person's email factor. */
    private Factor $factor;

    /** @var \SineMacula\Laravel\Mfa\Testing\FakeEmailSender The codes sent. */
    private FakeEmailSender $mailbox;

    /**
     * Enable email codes and recovery codes, sign one person in through the
     * guard, and give another, signing in on a pending session, an email
     * factor.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        config()->set('hashing.bcrypt.rounds', 4);
        config()->set('mfa.applications.web', [
            'types'          => ['email'],
            'recovery_codes' => ['enabled' => true],
            'first_factor'   => ['method' => 'password', 'channel' => 'password'],
        ]);

        $this->mailbox = FakeEmailSender::fake($this->container());

        /** @var \Tests\Fixtures\Identities\TestUser $guarded */
        $guarded = TestUser::query()->create(['email' => 'guarded@example.test']);

        /** @var \Tests\Fixtures\Identities\TestUser $pending */
        $pending = TestUser::query()->create(['email' => 'pending@example.test']);

        $this->guarded = $guarded;
        $this->pending = $pending;
        $this->factor  = $this->emailFactor($pending, 'pending@example.test');

        $this->emailFactor($guarded, 'guarded@example.test');
        $this->actingAs($guarded);
    }

    /**
     * A pending session that allows none of what the helpers need gets
     * nothing from any of them, and the guard's user is not served instead.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPendingSessionWithoutTheActionGetsNothing(): void
    {
        $this->pendingSession([PendingAction::START_BOOTSTRAP_ENROLLMENT]);

        self::assertNull($this->manager()->getFactors());
        self::assertNull($this->manager()->challenge('email', $this->factor));
        self::assertFalse($this->manager()->verify('email', $this->factor, '123456'));
        self::assertFalse($this->manager()->redeemRecoveryCode('ABCDEFGHJKLM'));
        self::assertSame([], $this->manager()->generateRecoveryCodes());
        self::assertSame([], $this->mailbox->sent());
        self::assertSame(0, RecoveryCode::query()->count());
    }

    /**
     * Listing factors on a pending session that allows it lists the pending
     * person's, not the guard's user's.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testListingServesThePendingPerson(): void
    {
        $this->pendingSession([PendingAction::LIST_FACTORS]);

        self::assertSame([$this->factor->id], $this->manager()->getFactors()?->map(static fn (FactorContract $factor): mixed => $factor->getFactorIdentifier())->all());
    }

    /**
     * A code is sent to the pending person's factor and verified on the
     * pending session that allows both.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSendingAndVerifyingServeThePendingPerson(): void
    {
        $this->pendingSession([PendingAction::SEND_CODE, PendingAction::VERIFY]);

        self::assertTrue($this->manager()->challenge('email', $this->factor)?->wasSent());

        $code = $this->mailbox->lastCodeTo('pending@example.test');

        self::assertNotNull($code);
        self::assertNull($this->mailbox->lastCodeTo('guarded@example.test'));
        self::assertTrue($this->manager()->verify('email', $this->factor, $code));
    }

    /**
     * Sending is not verifying: a pending session that allows only sending
     * cannot verify the code it was sent.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEachActionIsCheckedOnItsOwn(): void
    {
        $this->pendingSession([PendingAction::SEND_CODE]);

        $this->manager()->challenge('email', $this->factor);

        self::assertFalse($this->manager()->verify('email', $this->factor, (string) $this->mailbox->lastCodeTo('pending@example.test')));
    }

    /**
     * A pending credential that does not validate is refused by every helper,
     * never answered as the guard's user.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnInvalidPendingCredentialPropagates(): void
    {
        $this->container()->instance(PendingSessionResolver::class, new FixedPendingSessionResolver(invalid: true));

        $this->expectException(InvalidPendingCredentialException::class);

        $this->manager()->getFactors();
    }

    /**
     * Make every request carry the pending person's pending session, allowing
     * the actions.
     *
     * @param  list<\SineMacula\Laravel\Mfa\Enums\PendingAction>  $actions
     * @return void
     */
    private function pendingSession(array $actions): void
    {
        $first = SignInProofs::of($this->pending)->inSession('pending-1')->password();

        $this->container()->instance(PendingSessionResolver::class, new FixedPendingSessionResolver(
            new PendingContext($this->pending, 'web', 'pending-1', $first, Requirement::none()->withAdditionalVerification(), $actions),
        ));
    }

    /**
     * A confirmed email factor of the person's.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @param  string  $address
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function emailFactor(TestUser $user, string $address): Factor
    {
        /** @var \SineMacula\Laravel\Mfa\Models\Factor */
        return Factor::query()->create([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->id,
            'type'                 => 'email',
            'destination'          => $address,
            'status'               => 'confirmed',
            'confirmed_at'         => CarbonImmutable::now(),
        ]);
    }

    /**
     * The manager.
     *
     * @return \SineMacula\Laravel\Mfa\MfaManager
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function manager(): MfaManager
    {
        /** @var \SineMacula\Laravel\Mfa\MfaManager */
        return $this->container()->make('mfa');
    }
}
