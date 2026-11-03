<?php

declare(strict_types = 1);

namespace Tests\Unit\Codes;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Codes\PackageChallengeGateway;
use SineMacula\Laravel\Mfa\Context\PendingContext;
use SineMacula\Laravel\Mfa\Contracts\ChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Exceptions\UnsupportedFactorException;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Testing\FakeEmailSender;
use Tests\Fixtures\Codes\Concerns\ArrangesEmailChallenges;
use Tests\Fixtures\Context\FixedPendingSessionResolver;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Requirements\SignInProofs;
use Tests\TestCase;

/**
 * Tests for `PackageChallengeGateway`, the package's own codes as a challenge
 * gateway: it serves only the request's caller, asks the counters before it
 * sends or checks, and sends only for a type that delivers codes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PackageChallengeGateway::class)]
final class PackageChallengeGatewayTest extends TestCase
{
    use ArrangesEmailChallenges;

    /** @var \Tests\Fixtures\Identities\TestUser The person challenged. */
    private TestUser $user;

    /** @var \SineMacula\Laravel\Mfa\Models\Factor The person's email factor. */
    private Factor $factor;

    /** @var \SineMacula\Laravel\Mfa\Testing\FakeEmailSender The codes sent. */
    private FakeEmailSender $mailbox;

    /**
     * Sign a person in with an email factor.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        [$this->user, $this->factor, $this->mailbox] = $this->arrangeEmailChallenges();
    }

    /**
     * A code is sent for the caller's factor and answers its challenge.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSendsAndVerifiesTheCallersCode(): void
    {
        $binding = $this->emailBinding($this->user);
        $sent    = $this->gateway()->send($this->factor, $binding);

        self::assertTrue($sent->wasSent());
        self::assertNotNull($sent->challengeId);
        self::assertTrue($this->gateway()->verify($this->factor, $binding, $sent->challengeId, self::lastEmailedCode($this->mailbox))->hasPassed());
    }

    /**
     * A binding that does not name the request's caller is sent nothing and
     * verifies nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testServesOnlyTheCaller(): void
    {
        $binding = new ProofBinding(TestUser::class, 'someone-else', 'web', self::CHALLENGE_SESSION, Purpose::SIGN_IN);

        self::assertSame(FailureReason::NOT_FOUND, $this->gateway()->verify($this->factor, $binding, 'challenge-1', '123456')->reason);
        self::assertFalse($this->gateway()->verify($this->factor, $binding, 'challenge-1', '123456')->counted);
        self::assertSame(FailureReason::NOT_FOUND, $this->gateway()->send($this->factor, $binding)->reason);
    }

    /**
     * A caller with no sign-in the proof store knows of is sent nothing and
     * verifies nothing, under the binding of the sign-in it had.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Throwable
     */
    public function testServesNothingWithoutASignIn(): void
    {
        $binding = $this->emailBinding($this->user);

        $this->container()->make(ProofStore::class)->forget($this->user, self::CHALLENGE_APPLICATION);

        $outcome = $this->gateway()->verify($this->factor, $binding, 'challenge-1', '123456');

        self::assertSame(FailureReason::NOT_FOUND, $outcome->reason);
        self::assertFalse($outcome->counted);
        self::assertSame(FailureReason::NOT_FOUND, $this->gateway()->send($this->factor, $binding)->reason);
        self::assertSame([], $this->mailbox->sent());
    }

    /**
     * A pending session that does not allow sending or verifying is served
     * nothing, though the guard's user is the factor's owner.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testServesAPendingSessionOnlyWhatItAllows(): void
    {
        $proofs = SignInProofs::of($this->user)->inSession(self::CHALLENGE_SESSION);

        $this->container()->instance(PendingSessionResolver::class, new FixedPendingSessionResolver(
            new PendingContext(
                $this->user,
                'web',
                self::CHALLENGE_SESSION,
                $proofs->password(),
                Requirement::none(),
                [PendingAction::LIST_FACTORS],
                CarbonImmutable::now()->addHour(),
            ),
        ));

        self::assertFalse($this->gateway()->verify($this->factor, $this->emailBinding($this->user), 'challenge-1', '123456')->hasPassed());
        self::assertSame(FailureReason::NOT_FOUND, $this->gateway()->send($this->factor, $this->emailBinding($this->user))->reason);
        self::assertSame([], $this->mailbox->sent());
    }

    /**
     * A binding of the caller's own sign-in on another application, or of
     * another session on its own, is sent nothing and verifies nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRefusesABindingOfTheCallersOtherApplicationOrSession(): void
    {
        config()->set('mfa.applications.admin', [
            'types'        => ['email'],
            'first_factor' => ['method' => 'password', 'channel' => 'password'],
        ]);

        $this->container()->make(ProofStore::class)->begin($this->user, 'admin', 'admin-sign-in');

        $owner = ProofOwner::of($this->user);

        foreach ([['admin', 'admin-sign-in'], ['web', 'another-sign-in']] as [$application, $session]) {
            $binding = new ProofBinding($owner->type, $owner->key, $application, $session, Purpose::SIGN_IN);

            self::assertFalse($this->gateway()->verify($this->factor, $binding, 'challenge-1', '123456')->hasPassed());
            self::assertSame(FailureReason::NOT_FOUND, $this->gateway()->send($this->factor, $binding)->reason);
        }

        self::assertSame([], $this->mailbox->sent());
    }

    /**
     * A pending session on one application is served only for its own binding,
     * never for the same identity's active sign-in on another.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPendingSessionNeverReachesAnActiveSignInElsewhere(): void
    {
        config()->set('mfa.applications.admin', [
            'types'        => ['email'],
            'first_factor' => ['method' => 'password', 'channel' => 'password'],
        ]);

        $proofs = SignInProofs::of($this->user)->onApplication('admin')->inSession('pending-1');

        $this->container()->instance(PendingSessionResolver::class, new FixedPendingSessionResolver(
            new PendingContext(
                $this->user,
                'admin',
                'pending-1',
                $proofs->password(),
                Requirement::none(),
                [PendingAction::SEND_CODE, PendingAction::VERIFY],
                CarbonImmutable::now()->addHour(),
            ),
        ));

        $active = $this->emailBinding($this->user);

        self::assertFalse($this->gateway()->verify($this->factor, $active, 'challenge-1', '123456')->hasPassed());
        self::assertSame(FailureReason::NOT_FOUND, $this->gateway()->send($this->factor, $active)->reason);
        self::assertSame([], $this->mailbox->sent());

        $owner     = ProofOwner::of($this->user);
        $pending   = new ProofBinding($owner->type, $owner->key, 'admin', 'pending-1', Purpose::SIGN_IN);
        $challenge = $this->gateway()->send($this->factor, $pending)->challengeId;

        self::assertNotNull($challenge);
        self::assertTrue($this->gateway()->verify($this->factor, $pending, $challenge, self::lastEmailedCode($this->mailbox))->hasPassed());
    }

    /**
     * A disabled factor is sent nothing, and its code is not checked.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALockedFactorIsNotChallenged(): void
    {
        $binding   = $this->emailBinding($this->user);
        $challenge = $this->gateway()->send($this->factor, $binding)->challengeId;
        $code      = self::lastEmailedCode($this->mailbox);

        self::assertNotNull($challenge);

        $this->factor->update(['disabled_at' => CarbonImmutable::now()]);

        $refused = $this->gateway()->verify($this->factor, $binding, $challenge, $code);

        self::assertSame(FailureReason::LOCKED, $refused->reason);
        self::assertFalse($refused->counted);
        self::assertNull($refused->lockedUntil);
        self::assertSame(FailureReason::LOCKED, $this->gateway()->send($this->factor, $binding)->reason);

        $this->factor->update(['disabled_at' => null]);

        self::assertTrue($this->gateway()->verify($this->factor, $binding, $challenge, $code)->hasPassed());
    }

    /**
     * A factor under a timed lockout is refused with when the lockout ends, and
     * how long a send must wait.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALockoutsTimeIsReported(): void
    {
        $this->travelTo(CarbonImmutable::parse('2026-11-01 12:00:00'));

        $binding   = $this->emailBinding($this->user);
        $challenge = $this->gateway()->send($this->factor, $binding)->challengeId;
        $until     = CarbonImmutable::now()->addMinutes(5);

        self::assertNotNull($challenge);

        $this->factor->update(['locked_until' => $until]);

        self::assertSame($until->getTimestamp(), $this->gateway()->verify($this->factor, $binding, $challenge, '000000')->lockedUntil?->getTimestamp());
        self::assertSame(300, $this->gateway()->send($this->factor, $binding)->retryAfter);
    }

    /**
     * A wrong code, an expired challenge and an absent one are each counted,
     * and carry their own reason and internal detail.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailureIsCountedWithItsReason(): void
    {
        $binding   = $this->emailBinding($this->user);
        $challenge = $this->gateway()->send($this->factor, $binding)->challengeId;

        self::assertNotNull($challenge);

        $wrong = $this->gateway()->verify($this->factor, $binding, $challenge, '000000');

        self::assertSame(FailureReason::INVALID_CODE, $wrong->reason);
        self::assertSame('The code did not match.', $wrong->detail);
        self::assertTrue($wrong->counted);

        $unknown = $this->gateway()->verify($this->factor, $binding, 'unknown', '000000');

        self::assertSame(FailureReason::NOT_FOUND, $unknown->reason);
        self::assertTrue($unknown->counted);
        self::assertSame(2, Factor::query()->findOrFail($this->factor->id)->getConsecutiveFailures());
    }

    /**
     * A factor whose type does not deliver codes is refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATypeThatDeliversNoCodesIsRefused(): void
    {
        $totp = $this->factor->replicate();

        $totp->setAttribute('type', 'totp');
        $totp->save();

        $this->expectException(UnsupportedFactorException::class);
        $this->expectExceptionMessage('The factor\'s type [totp] does not deliver codes.');

        $this->gateway()->send($totp, $this->emailBinding($this->user));
    }

    /**
     * The bound gateway.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\ChallengeGateway
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function gateway(): ChallengeGateway
    {
        return $this->container()->make(ChallengeGateway::class);
    }
}
