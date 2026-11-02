<?php

declare(strict_types = 1);

namespace Tests\Unit\Codes;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Codes\PackageChallengeGateway;
use SineMacula\Laravel\Mfa\Context\PendingContext;
use SineMacula\Laravel\Mfa\Contracts\ChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Exceptions\UnsupportedFactorException;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
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
        $binding   = $this->emailBinding($this->user);
        $challenge = $this->gateway()->send($this->factor, $binding);

        self::assertNotSame('', $challenge);
        self::assertTrue($this->gateway()->verify($this->factor, $binding, $challenge, self::lastEmailedCode($this->mailbox)));
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

        self::assertFalse($this->gateway()->verify($this->factor, $binding, 'challenge-1', '123456'));

        $this->expectException(OperationRefusedException::class);

        $this->gateway()->send($this->factor, $binding);
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
            new PendingContext($this->user, 'web', self::CHALLENGE_SESSION, $proofs->password(), Requirement::none(), [PendingAction::LIST_FACTORS]),
        ));

        self::assertFalse($this->gateway()->verify($this->factor, $this->emailBinding($this->user), 'challenge-1', '123456'));
        self::assertSame(FailureReason::NOT_FOUND, $this->refusal(fn () => $this->gateway()->send($this->factor, $this->emailBinding($this->user))));
        self::assertSame([], $this->mailbox->sent());
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
        $challenge = $this->gateway()->send($this->factor, $binding);
        $code      = self::lastEmailedCode($this->mailbox);

        $this->factor->update(['disabled_at' => CarbonImmutable::now()]);

        self::assertFalse($this->gateway()->verify($this->factor, $binding, $challenge, $code));
        self::assertSame(FailureReason::LOCKED, $this->refusal(fn () => $this->gateway()->send($this->factor, $binding)));

        $this->factor->update(['disabled_at' => null]);

        self::assertTrue($this->gateway()->verify($this->factor, $binding, $challenge, $code));
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
     * The reason the call was refused with.
     *
     * @param  \Closure(): mixed  $call
     * @return \SineMacula\Laravel\Mfa\Enums\FailureReason
     */
    private function refusal(\Closure $call): FailureReason
    {
        try {
            $call();
        } catch (OperationRefusedException $exception) {
            return $exception->reason;
        }

        self::fail('The call was expected to be refused.');
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
