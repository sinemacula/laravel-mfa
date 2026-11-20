<?php

declare(strict_types = 1);

namespace Tests\Integration\Secrets;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Crypt;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Attempts\AttemptKeys;
use SineMacula\Laravel\Mfa\Attempts\AttemptStore;
use SineMacula\Laravel\Mfa\Codes\CodeKeys;
use SineMacula\Laravel\Mfa\Enums\CodeCheck;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Models\IdentityState;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use SineMacula\Laravel\Mfa\Verification\Submission;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Secrets\RecordedTrace;
use Tests\Fixtures\Verification\Concerns\ArrangesVerification;
use Tests\TestCase;

/**
 * Rotating `app.key`: TOTP secrets survive while the old key stays in
 * `APP_PREVIOUS_KEYS`; delivered codes and throttle windows end, while the
 * identity send cap and stored lockouts stand.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Factor::class)]
#[CoversClass(CodeKeys::class)]
#[CoversClass(AttemptKeys::class)]
final class KeyRotationTest extends TestCase
{
    use ArrangesVerification, RefreshDatabase;

    /** @var string */
    private const string IP = '203.0.113.7';

    /**
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeVerification();
    }

    /**
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testASecretEncryptedUnderAPreviousKeyVerifies(): void
    {
        $previous = self::newKey();

        $this->useKeys($previous);

        $factor = $this->totpFactor($this->person());

        $this->useKeys(self::newKey(), $previous);

        $reloaded = Factor::query()->findOrFail($factor->id);

        self::assertSame(AuthenticatorApp::SECRET, $reloaded->secret);

        $binding = new ProofBinding('user', '1', 'web', 'sign-in-1', Purpose::STEP_UP);

        self::assertSame(CodeCheck::ACCEPTED, Mfa::driver('totp')->verify($reloaded, AuthenticatorApp::code($reloaded), $binding));
    }

    /**
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheSecretIsStoredEncrypted(): void
    {
        $this->useKeys(self::newKey());

        $factor = $this->totpFactor($this->person());

        $stored = $factor->getConnection()->table($factor->getTable())->where('id', $factor->id)->value('secret');

        self::assertIsString($stored);
        self::assertStringNotContainsString(AuthenticatorApp::SECRET, $stored);
    }

    /**
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testASecretUnderADroppedKeyDoesNotDecrypt(): void
    {
        $this->useKeys(self::newKey());

        $factor = $this->totpFactor($this->person());

        $this->useKeys(self::newKey());

        $reloaded = Factor::query()->findOrFail($factor->id);

        $this->expectException(DecryptException::class);

        self::fail((string) $reloaded->secret);
    }

    /**
     * The decrypt failure propagates and counts nothing towards a lockout.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAFactorUnderADroppedKeyIsAServerErrorNotAWrongCode(): void
    {
        $this->useKeys(self::newKey());

        $user   = $this->signedInPerson();
        $factor = $this->totpFactor($user);
        $code   = AuthenticatorApp::code($factor);

        $this->requestFrom(self::IP);
        $this->useKeys(self::newKey());
        $this->forgetReports();

        $exception = RecordedTrace::thrownBy(static fn () => Mfa::verify(Callers::current(), Submission::factor($factor->id, $code)));

        self::assertInstanceOf(DecryptException::class, $exception);
        self::assertSame([], $this->reported);
        self::assertSame(0, $this->factorRun($factor));
        self::assertSame(0, $this->identityRun($user));
        self::assertSame(0, $this->addressHits(self::IP));
        self::assertSame([], $this->furtherProofs($user));
    }

    /**
     * The open challenge is no longer found, so a new one starts at once with
     * the destination's count and cooldown left behind.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAnOutstandingCodeEndsWithTheKeyItWasSentUnder(): void
    {
        config()->set('mfa.codes.factor_send_limit', 1);

        $previous = self::newKey();

        $this->useKeys($previous);

        $user   = $this->signedInPerson();
        $factor = $this->emailFactor($user);

        [$challenge, $code] = $this->sentCode($factor);

        $this->requestFrom(self::IP);
        $this->useKeys(self::newKey(), $previous);

        $result = Mfa::verify(Callers::current(), Submission::challenge($factor->id, $challenge, $code));

        self::assertSame(FailureReason::NOT_FOUND, $result->reason);
        self::assertSame(1, $this->factorRun($factor));
        self::assertSame(1, $this->identityRun($user));
        self::assertSame(1, $this->addressHits(self::IP));

        [$next] = $this->sentCode($factor);

        self::assertNotSame($challenge, $next);
        self::assertCount(2, $this->mailbox->sent());
    }

    /**
     * Sent to another destination, so neither a cooldown nor the destination's
     * count can be what refuses it.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheIdentitySendCapOutlivesARotation(): void
    {
        config()->set('mfa.codes.identity_send_limit', 1);

        $previous = self::newKey();

        $this->useKeys($previous);

        $user = $this->signedInPerson();

        $this->sentCode($this->emailFactor($user));

        $this->useKeys(self::newKey(), $previous);

        $other = $this->emailFactor($user, 'other@example.test');

        self::assertSame(FailureReason::SENDING_CAPPED, Mfa::sendCode(Callers::current(), $other->id)->reason);
        self::assertCount(1, $this->mailbox->sent());
    }

    /**
     * The windows start afresh, but the stored lockout still refuses; it ends
     * after the lockout, not with the old address window.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAnIdentityLockoutOutlivesARotation(): void
    {
        config()->set('mfa.attempts.identity_limit', 2);

        [$user, $factor] = $this->failTwiceThenRotate();

        $owner  = ProofOwner::of($user);
        $window = $this->container()->make(AttemptKeys::class)->identity($owner->type, $owner->key);

        self::assertSame([], $this->container()->make(AttemptStore::class)->read([$window]));
        self::assertSame(2, $this->identityRun($user));

        $result = Mfa::verify(Callers::current(), Submission::factor($factor->id, AuthenticatorApp::code($factor)));
        $state  = IdentityState::query()->where('authenticatable_type', $owner->type)->where('authenticatable_id', $owner->key)->sole();

        self::assertSame(FailureReason::LOCKED, $result->reason);
        self::assertEquals(CarbonImmutable::now()->addSeconds(900), $result->lockedUntil);
        self::assertEquals($result->lockedUntil, $state->locked_until);
    }

    /**
     * The fresh address window admits and counts another factor's attempt.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAFactorLockoutOutlivesARotation(): void
    {
        config()->set('mfa.attempts.factor_limit', 2);

        [$user, $factor] = $this->failTwiceThenRotate();

        self::assertSame(2, $this->factorRun($factor));

        $result = Mfa::verify(Callers::current(), Submission::factor($factor->id, AuthenticatorApp::code($factor)));

        self::assertSame(FailureReason::LOCKED, $result->reason);
        self::assertEquals(CarbonImmutable::now()->addSeconds(900), $result->lockedUntil);
        self::assertEquals($result->lockedUntil, Factor::query()->whereKey($factor->id)->sole()->getLockedUntil());

        $other = $this->totpFactor($user);

        self::assertSame(FailureReason::INVALID_CODE, Mfa::verify(Callers::current(), Submission::factor($other->id, AuthenticatorApp::code($other, 10)))->reason);
        self::assertSame(1, $this->addressHits(self::IP));
    }

    /**
     * Two wrong TOTP codes fill the address window, which ends before a lockout
     * would, then the key is rotated with the old one kept.
     *
     * @return array{0: \Tests\Fixtures\Identities\TestUser, 1: \SineMacula\Laravel\Mfa\Models\Factor}
     *
     * @throws \Random\RandomException
     */
    private function failTwiceThenRotate(): array
    {
        config()->set('mfa.attempts.ip_limit', 2);
        config()->set('mfa.attempts.window_seconds', 600);

        $previous = self::newKey();

        $this->useKeys($previous);

        $user   = $this->signedInPerson();
        $factor = $this->totpFactor($user);

        $this->requestFrom(self::IP);

        foreach ([10, 11] as $steps) {
            Mfa::verify(Callers::current(), Submission::factor($factor->id, AuthenticatorApp::code($factor, $steps)));
        }

        self::assertSame(2, $this->addressHits(self::IP));

        $this->useKeys(self::newKey(), $previous);

        self::assertSame(0, $this->addressHits(self::IP));

        return [$user, $factor];
    }

    /**
     * @param  string  $key
     * @param  string  ...$previous
     * @return void
     */
    private function useKeys(string $key, string ...$previous): void
    {
        config()->set('app.key', $key);
        config()->set('app.previous_keys', $previous);

        $this->container()->forgetInstance('encrypter');

        Crypt::clearResolvedInstance('encrypter');
    }

    /**
     * @return string
     *
     * @throws \Random\RandomException
     */
    private static function newKey(): string
    {
        return 'base64:' . base64_encode(random_bytes(32));
    }
}
