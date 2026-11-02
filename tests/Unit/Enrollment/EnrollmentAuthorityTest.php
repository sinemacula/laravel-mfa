<?php

declare(strict_types = 1);

namespace Tests\Unit\Enrollment;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Context\Caller;
use SineMacula\Laravel\Mfa\Context\PendingContext;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Contracts\Reauthenticator;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentAuthority;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Passkeys\Concerns\ArrangesPasskeys;
use Tests\Fixtures\Requirements\SignInProofs;
use Tests\Fixtures\Seams\FreshReauthenticator;
use Tests\TestCase;

/**
 * Tests for `EnrollmentAuthority`: when a caller may add a factor of a type,
 * on an active session and on a pending one, and the application's limits.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EnrollmentAuthority::class)]
final class EnrollmentAuthorityTest extends TestCase
{
    use ArrangesPasskeys;

    /**
     * A first factor on an active session needs a reauthentication of the
     * current sign-in, made in the last five minutes.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAFirstFactorNeedsAFreshReauthentication(): void
    {
        CarbonImmutable::setTestNow(CarbonImmutable::now());

        $this->enablePasskeys();

        $user  = $this->signedInPerson();
        $store = $this->container()->make(ProofStore::class);

        self::assertSame(FailureReason::NOT_FRESH, $this->refusal(new Caller($user), 'passkey'));

        $this->container()->instance(Reauthenticator::class, new FreshReauthenticator($store, 0, 'another-sign-in'));

        self::assertSame(FailureReason::NOT_FRESH, $this->refusal(new Caller($user), 'passkey'));

        $this->container()->instance(Reauthenticator::class, new FreshReauthenticator($store, EnrollmentAuthority::REAUTHENTICATION_MAX_AGE + 1));

        self::assertSame(FailureReason::NOT_FRESH, $this->refusal(new Caller($user), 'passkey'));

        $this->container()->instance(Reauthenticator::class, new FreshReauthenticator($store, EnrollmentAuthority::REAUTHENTICATION_MAX_AGE));

        self::assertNull($this->refusal(new Caller($user), 'passkey'));

        CarbonImmutable::setTestNow();
    }

    /**
     * Without a sign-in the reauthenticator is not asked.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testWithoutASignInTheReauthenticatorIsNotAsked(): void
    {
        $this->enablePasskeys();

        $user            = $this->signedInPerson();
        $reauthenticator = new FreshReauthenticator($this->container()->make(ProofStore::class));

        $this->container()->instance(Reauthenticator::class, $reauthenticator);
        $this->container()->make(ProofStore::class)->forget($user, self::APPLICATION);

        self::assertSame(FailureReason::NOT_FRESH, $this->refusal(new Caller($user), 'passkey'));
        self::assertSame(0, $reauthenticator->asked);
    }

    /**
     * A pending session may add a factor only on the bootstrap path: its
     * credential allows it, the application allows bootstrap for the type,
     * and the identity has no confirmed factor.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAPendingSessionNeedsTheBootstrapPath(): void
    {
        $this->enablePasskeys();

        $user = $this->signedInPerson();

        self::assertSame(FailureReason::NOT_FRESH, $this->refusal($this->pending($user, [PendingAction::VERIFY]), 'passkey'));
        self::assertSame(FailureReason::MFA_ENROLLMENT_REQUIRED, $this->refusal($this->pending($user), 'passkey'));

        $this->enablePasskeys(['bootstrap' => ['enabled' => true, 'types' => ['totp']]]);

        self::assertSame(FailureReason::TYPE_NOT_ENABLED, $this->refusal($this->pending($user), 'passkey'));
        self::assertNull($this->refusal($this->pending($user), 'totp'));

        $this->confirmedFactor($user);

        self::assertSame(FailureReason::NOT_FRESH, $this->refusal($this->pending($user), 'totp'));
    }

    /**
     * The limits on confirmed factors enrolled through the application, of
     * the type and in all, apply; factors enrolled elsewhere do not count.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheLimitsApplyToFactorsEnrolledThroughTheApplication(): void
    {
        $this->enablePasskeys(['limits' => ['confirmed' => 2, 'confirmed_per_type' => 1]]);

        $user = $this->signedInPerson();
        $totp = $this->confirmedFactor($user);

        $this->stepUpWith($user, $totp);

        self::assertSame(FailureReason::LIMIT_REACHED, $this->refusal(new Caller($user), 'totp'));
        self::assertNull($this->refusal(new Caller($user), 'passkey'));

        $this->confirmedFactor($user, 'passkey', self::CREDENTIAL);

        self::assertSame(FailureReason::LIMIT_REACHED, $this->refusal(new Caller($user), 'sms'));

        Factor::query()->update(['application' => 'admin']);

        self::assertNull($this->refusal(new Caller($user), 'totp'));
    }

    /**
     * A pending context of the person's, allowing the actions given or the
     * bootstrap confirmation.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @param  list<\SineMacula\Laravel\Mfa\Enums\PendingAction>  $actions
     * @return \SineMacula\Laravel\Mfa\Context\Caller
     */
    private function pending(TestUser $user, array $actions = [PendingAction::CONFIRM_BOOTSTRAP_ENROLLMENT]): Caller
    {
        $first = SignInProofs::of($user)->inSession('pending-1')->password();

        return new Caller($user, new PendingContext($user, self::APPLICATION, 'pending-1', $first, Requirement::none(), $actions));
    }

    /**
     * The reason the caller is refused a factor of the type, or `null` when
     * it is not.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\Caller  $caller
     * @param  string  $type
     * @return ?\SineMacula\Laravel\Mfa\Enums\FailureReason
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function refusal(Caller $caller, string $type): ?FailureReason
    {
        try {
            $this->container()->make(EnrollmentAuthority::class)->authorize($caller, self::APPLICATION, $type, Factor::query()->get());
        } catch (OperationRefusedException $exception) {
            return $exception->reason;
        }

        return null;
    }
}
