<?php

declare(strict_types = 1);

namespace Tests\Feature\Events;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Context\PendingContext;
use SineMacula\Laravel\Mfa\Contracts\EventContextResolver;
use SineMacula\Laravel\Mfa\Contracts\MfaEvent;
use SineMacula\Laravel\Mfa\Contracts\PendingCompletion;
use SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Events\EventDispatcher;
use SineMacula\Laravel\Mfa\Events\FactorConfirmed;
use SineMacula\Laravel\Mfa\Events\PasskeyAssociated;
use SineMacula\Laravel\Mfa\Events\RecoveryCodesGenerated;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyChangeGate;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeIssuance;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use Tests\Fixtures\Context\FixedPendingSessionResolver;
use Tests\Fixtures\Passkeys\Concerns\ArrangesPasskeys;
use Tests\Fixtures\Passkeys\StandInRegistrar;
use Tests\Fixtures\Requirements\SignInProofs;
use Tests\Fixtures\Seams\CheckingCompletion;
use Tests\Fixtures\Seams\RecordingEventContextResolver;
use Tests\TestCase;

/**
 * A passkey registered as a pending session's bootstrap enrolment names the
 * pending session's sign-in the registration was bound to, on every event it
 * reports, not the sign-in the proof store holds for the identity.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EventDispatcher::class)]
#[CoversClass(PasskeyChangeGate::class)]
#[CoversClass(RecoveryCodeIssuance::class)]
final class PasskeyEventSignInTest extends TestCase
{
    use ArrangesPasskeys;

    /** @var string The session id of the pending session. */
    private const string PENDING = 'pending-1';

    /** @var list<\SineMacula\Laravel\Mfa\Contracts\MfaEvent> What was reported, oldest first. */
    private array $reported = [];

    /**
     * Make recovery codes quick to hash, bind the recording resolver and listen
     * for every event.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        config()->set('hashing.bcrypt.rounds', 4);

        $this->container()->instance(EventContextResolver::class, new RecordingEventContextResolver);

        Event::listen(MfaEvent::class, function (MfaEvent $event): void {
            $this->reported[] = $event;
        });
    }

    /**
     * A bootstrap registration names the pending session's sign-in on the
     * confirmation, the association and the recovery codes issued with the
     * first factor.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABootstrapRegistrationNamesThePendingSignIn(): void
    {
        $this->enablePasskeys(['recovery_codes' => ['enabled' => true], 'bootstrap' => ['enabled' => true, 'types' => ['passkey']]]);

        $user    = $this->signedInPerson();
        $proofs  = SignInProofs::of($user)->inSession(self::PENDING);
        $actions = [PendingAction::CONFIRM_BOOTSTRAP_ENROLLMENT];
        $pending = new PendingContext($user, self::APPLICATION, self::PENDING, $proofs->password(), Requirement::none(), $actions, CarbonImmutable::now()->addHour());

        $this->container()->instance(PendingSessionResolver::class, new FixedPendingSessionResolver($pending));
        $this->container()->instance(PendingCompletion::class, new CheckingCompletion(self::PENDING));

        $gate   = $this->container()->make(PasskeyChangeGate::class);
        $result = (new StandInRegistrar($gate))->register($user, self::APPLICATION, $this->registration($user, session: self::PENDING));

        self::assertNotNull($result);
        self::assertCount(10, $result->recoveryCodes);
        self::assertSame([self::PENDING], RecordingEventContextResolver::signInsOf($this->reported, FactorConfirmed::class));
        self::assertSame([self::PENDING], RecordingEventContextResolver::signInsOf($this->reported, PasskeyAssociated::class));
        self::assertSame([self::PENDING], RecordingEventContextResolver::signInsOf($this->reported, RecoveryCodesGenerated::class));
        self::assertSame(self::SESSION, $this->container()->make(ProofStore::class)->currentSession($user, self::APPLICATION));
    }
}
