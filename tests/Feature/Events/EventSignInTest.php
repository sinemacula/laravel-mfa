<?php

declare(strict_types = 1);

namespace Tests\Feature\Events;

use Illuminate\Support\Carbon;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\EventContextResolver;
use SineMacula\Laravel\Mfa\Events\Actor;
use SineMacula\Laravel\Mfa\Events\EventDispatcher;
use SineMacula\Laravel\Mfa\Events\EventSubject;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use SineMacula\Laravel\Mfa\Verification\Submission;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Seams\RecordingEventContextResolver;
use Tests\Fixtures\Verification\Concerns\ArrangesVerification;
use Tests\TestCase;

/**
 * The event context resolver is handed the sign-in an operation was bound to,
 * where the operation captured one: a pending session's, and the active sign-in
 * a verification is bound to. An operator's action names none.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EventDispatcher::class)]
#[CoversClass(EventSubject::class)]
final class EventSignInTest extends TestCase
{
    use ArrangesVerification;

    /** @var \Tests\Fixtures\Seams\RecordingEventContextResolver The resolver that records what it is handed. */
    private RecordingEventContextResolver $resolver;

    /**
     * Arrange the application and bind the recording resolver.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeVerification();

        $this->resolver = new RecordingEventContextResolver;

        $this->container()->instance(EventContextResolver::class, $this->resolver);
    }

    /**
     * Release the frozen clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();

        parent::tearDown();
    }

    /**
     * A verification on a pending session names the pending session's sign-in,
     * when it succeeds and when it fails.
     *
     * @return void
     */
    public function testAPendingVerificationNamesThePendingSignIn(): void
    {
        $user   = $this->person();
        $factor = $this->totpFactor($user);

        $this->pendingSession($user);
        $this->beginSignIn($user, self::PENDING);

        self::assertFalse($this->mfa()->verify(Callers::current(), Submission::factor($factor->id, '000000'))->isVerified());
        self::assertTrue($this->mfa()->verify(Callers::current(), Submission::factor($factor->id, AuthenticatorApp::code($factor)))->isVerified());
        self::assertNotSame([], $this->resolver->signIns());
        self::assertSame([self::PENDING], array_values(array_unique($this->resolver->signIns())));
    }

    /**
     * A verification on an active session names the sign-in its proof is bound
     * to.
     *
     * @return void
     */
    public function testAnActiveVerificationNamesItsSignIn(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->totpFactor($user);

        self::assertTrue($this->mfa()->verify(Callers::current(), Submission::factor($factor->id, AuthenticatorApp::code($factor)))->isVerified());
        self::assertContains(self::SESSION, $this->resolver->signIns());
        self::assertNotContains(null, array_slice($this->resolver->signIns(), -1));
    }

    /**
     * An operator's unlock names no sign-in.
     *
     * @return void
     */
    public function testAnOperatorsActionNamesNoSignIn(): void
    {
        $user   = $this->person();
        $factor = $this->totpFactor($user);

        $factor->update(['locked_until' => Carbon::now()->addHour()]);

        self::assertTrue($this->mfa()->unlockFactor($user, $factor->id, new Actor('admin', '9')));

        self::assertNotSame([], $this->resolver->subjects);
        self::assertSame([null], array_values(array_unique($this->resolver->signIns())));
    }
}
