<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Verification\Concerns;

use Carbon\Carbon;
use Carbon\CarbonImmutable;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Mfa\Assurance\ObservedProperties;
use SineMacula\Laravel\Mfa\Attempts\AttemptKeys;
use SineMacula\Laravel\Mfa\Attempts\AttemptStore;
use SineMacula\Laravel\Mfa\Context\PendingContext;
use SineMacula\Laravel\Mfa\Contracts\MfaEvent;
use SineMacula\Laravel\Mfa\Contracts\PasskeyGateway;
use SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Events\VerificationFailed;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Models\IdentityState;
use SineMacula\Laravel\Mfa\Models\PasskeyAssociation;
use SineMacula\Laravel\Mfa\Passkeys\CredentialId;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyAssertion;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Secrets\RevealedSecret;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use SineMacula\Laravel\Mfa\Testing\FakeEmailSender;
use SineMacula\Laravel\Mfa\Verification\Submission;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Context\FixedPendingSessionResolver;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Passkeys\FakePasskeyGateway;
use Tests\Fixtures\Requirements\SignInProofs;

/**
 * Arranges the verification tests on `web` with every code type and recovery
 * codes enabled, the clock frozen and every event recorded.
 *
 * @phpstan-require-extends \Tests\TestCase
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait ArrangesVerification
{
    /** @var string */
    protected const string APPLICATION = 'web';

    /** @var string */
    protected const string SESSION = 'sign-in-a';

    /** @var string */
    protected const string PENDING = 'pending-a';

    /** @var string Canonical credential id. */
    protected const string CREDENTIAL = 'Y3JlZGVudGlhbC1vbmU';

    /** @var string */
    protected const string ADDRESS = 'person@example.test';

    /** @var \SineMacula\Laravel\Mfa\Testing\FakeEmailSender */
    protected FakeEmailSender $mailbox;

    /** @var list<\SineMacula\Laravel\Mfa\Contracts\MfaEvent> Oldest first. */
    protected array $reported = [];

    /**
     * @return void
     */
    protected function arrangeVerification(): void
    {
        Carbon::setTestNow('2026-11-01 12:00:00');

        config()->set('hashing.bcrypt.rounds', 4);

        $this->enableApplication();

        $this->mailbox = FakeEmailSender::fake($this->container());

        Event::listen(MfaEvent::class, function (MfaEvent $event): void {
            $this->reported[] = $event;
        });
    }

    /**
     * @param  array<string, mixed>  $settings
     * @return void
     */
    protected function enableApplication(array $settings = []): void
    {
        config()->set('mfa.applications.' . self::APPLICATION, array_replace([
            'types'          => ['totp', 'email'],
            'recovery_codes' => ['enabled' => true],
            'first_factor'   => ['method' => 'password', 'channel' => 'password'],
        ], $settings));
    }

    /**
     * @param  string  $session
     * @return \Tests\Fixtures\Identities\TestUser
     */
    protected function signedInPerson(string $session = self::SESSION): TestUser
    {
        $user = $this->person();

        $this->actingAs($user);

        $this->beginSignIn($user, $session);

        return $user;
    }

    /**
     * @param  string  $email
     * @return \Tests\Fixtures\Identities\TestUser
     */
    protected function person(string $email = self::ADDRESS): TestUser
    {
        /** @var \Tests\Fixtures\Identities\TestUser */
        return TestUser::query()->create(['email' => $email]);
    }

    /**
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @param  string  $session
     * @return void
     */
    protected function beginSignIn(TestUser $user, string $session = self::SESSION): void
    {
        $this->container()->make(ProofStore::class)->begin($user, self::APPLICATION, $session);
    }

    /**
     * By default the pending session allows everything verification needs.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @param  list<\SineMacula\Laravel\Mfa\Enums\PendingAction>  $actions
     * @param  list<\SineMacula\Laravel\Mfa\Proofs\Proof>  $proofs
     * @param  string  $session
     * @param  ?\SineMacula\Laravel\Mfa\Proofs\Proof  $firstFactor
     * @param  ?\Carbon\CarbonImmutable  $expiresAt
     * @return \SineMacula\Laravel\Mfa\Context\PendingContext
     */
    protected function pendingSession(
        TestUser $user,
        ?Requirement $requirement = null,
        array $actions = [PendingAction::LIST_FACTORS, PendingAction::SEND_CODE, PendingAction::VERIFY],
        array $proofs = [],
        string $session = self::PENDING,
        ?Proof $firstFactor = null,
        ?CarbonImmutable $expiresAt = null,
    ): PendingContext {
        $firstFactor ??= SignInProofs::of($user)->inSession($session)->password(60);
        $expiresAt   ??= CarbonImmutable::now()->addMinutes(10);
        $pending = new PendingContext($user, self::APPLICATION, $session, $firstFactor, $requirement ?? Requirement::none(), $actions, $expiresAt, $proofs);

        $this->container()->instance(PendingSessionResolver::class, new FixedPendingSessionResolver($pending));

        return $pending;
    }

    /**
     * @return void
     */
    protected function noPendingSession(): void
    {
        $this->container()->instance(PendingSessionResolver::class, new FixedPendingSessionResolver);
    }

    /**
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @param  array<string, mixed>  $attributes
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    protected function totpFactor(TestUser $user, array $attributes = []): Factor
    {
        return $this->factorOf($user, [...AuthenticatorApp::FACTOR, ...$attributes]);
    }

    /**
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @param  string  $address
     * @param  array<string, mixed>  $attributes
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    protected function emailFactor(TestUser $user, string $address = self::ADDRESS, array $attributes = []): Factor
    {
        return $this->factorOf($user, ['type' => 'email', 'destination' => $address, ...$attributes]);
    }

    /**
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @param  array<string, mixed>  $attributes
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    protected function factorOf(TestUser $user, array $attributes): Factor
    {
        /** @var \SineMacula\Laravel\Mfa\Models\Factor */
        return Factor::query()->create([
            'authenticatable_type' => $user->getMorphClass(),
            'authenticatable_id'   => (string) $user->getKey(),
            'status'               => 'confirmed',
            'confirmed_at'         => CarbonImmutable::now(),
            ...$attributes,
        ]);
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Models\Factor  $factor
     * @param  ?\SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @return array{0: string, 1: string}
     */
    protected function sentCode(Factor $factor, ?Purpose $purpose = null): array
    {
        $challenge = $this->mfa()->sendCode(Callers::current(), $factor->id, $purpose)->challengeId;
        $code      = $this->mailbox->lastCodeTo((string) $factor->destination);

        Assert::assertNotNull($challenge, 'A code must be sent.');
        Assert::assertNotNull($code, 'A code must be delivered.');

        return [$challenge, $code];
    }

    /**
     * Generates recovery codes past the public path's gate and returns the
     * first in clear.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @return string
     */
    protected function recoveryCode(TestUser $user): string
    {
        $codes = $this->container()->make(RecoveryCodeService::class)->generate($user, self::APPLICATION);

        Assert::assertInstanceOf(RevealedSecret::class, $codes[0]);

        $this->forgetReports();

        return $codes[0]->reveal();
    }

    /**
     * A submission for the named route, with a passing code when one is known.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @param  string  $route
     * @return \SineMacula\Laravel\Mfa\Verification\Submission
     */
    protected function passingSubmission(TestUser $user, string $route): Submission
    {
        switch ($route) {
            case 'email':
                $factor = $this->emailFactor($user);

                [$challenge, $code] = $this->sentCode($factor);

                return Submission::challenge($factor->id, $challenge, $code);

            case 'recovery_code':
                $this->totpFactor($user);

                return Submission::recoveryCode($this->recoveryCode($user));

            case 'passkey':
                return Submission::assertion($this->passkeyFactor($user)->id, ['id' => self::CREDENTIAL]);

            default:
                $factor = $this->totpFactor($user);

                return Submission::factor($factor->id, AuthenticatorApp::code($factor));
        }
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Enums\FailureReason|\SineMacula\Laravel\Mfa\Passkeys\PasskeyAssertion|null  $assertion
     * @return \Tests\Fixtures\Passkeys\FakePasskeyGateway
     */
    protected function enablePasskeys(FailureReason|PasskeyAssertion|null $assertion = null): FakePasskeyGateway
    {
        $observed = new ObservedProperties(userPresence: true, userVerification: true, phishingResistance: true);
        $gateway  = new FakePasskeyGateway([self::CREDENTIAL], $assertion ?? new PasskeyAssertion(self::CREDENTIAL, $observed, 'passkey-challenge'));

        $this->container()->instance(PasskeyGateway::class, $gateway);

        $this->enableApplication(['types' => ['totp', 'email', 'passkey']]);

        return $gateway;
    }

    /**
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @param  string  $credential
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    protected function passkeyFactor(TestUser $user, #[\SensitiveParameter] string $credential = self::CREDENTIAL): Factor
    {
        $factor = $this->factorOf($user, ['type' => 'passkey', 'credential_reference' => $credential, 'application' => self::APPLICATION]);

        PasskeyAssociation::query()->create([
            'factor_id'            => $factor->id,
            'authenticatable_type' => $user->getMorphClass(),
            'authenticatable_id'   => (string) $user->getKey(),
            'credential_id_hash'   => CredentialId::hash($credential),
            'credential_id'        => $credential,
        ]);

        return $factor;
    }

    /**
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @param  string  $session
     * @return void
     */
    protected function recordFirstFactor(TestUser $user, string $session = self::SESSION): void
    {
        $proofs = SignInProofs::of($user)->inSession($session)->underGeneration(VerificationGeneration::current($user));

        $this->container()->make(ProofStore::class)->record($user, $proofs->password(60));
    }

    /**
     * Without a session named, reads whichever sign-in the store holds as
     * current, active or pending.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @param  ?string  $session
     * @return list<\SineMacula\Laravel\Mfa\Proofs\Proof>
     */
    protected function storedProofs(TestUser $user, ?string $session = null): array
    {
        $store = $this->container()->make(ProofStore::class);
        $session ??= $store->currentSession($user, self::APPLICATION);

        return $session === null ? [] : $store->proofs($user, self::APPLICATION, $session);
    }

    /**
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @return list<\SineMacula\Laravel\Mfa\Proofs\Proof>
     */
    protected function furtherProofs(TestUser $user): array
    {
        return array_values(array_filter($this->storedProofs($user), static fn (Proof $proof): bool => $proof->kind !== ProofKind::FIRST_FACTOR));
    }

    /**
     * @param  string  $ip
     * @return void
     */
    protected function requestFrom(string $ip): void
    {
        $this->container()->instance('request', Request::create('/', 'POST', server: ['REMOTE_ADDR' => $ip]));
    }

    /**
     * @param  string  $ip
     * @return int
     */
    protected function addressHits(string $ip): int
    {
        $key = $this->container()->make(AttemptKeys::class)->ip($ip);

        return $this->container()->make(AttemptStore::class)->read([$key])[$key]['hits'] ?? 0;
    }

    /**
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @return int
     */
    protected function identityRun(TestUser $user): int
    {
        $owner = ProofOwner::of($user);

        return IdentityState::query()->where('authenticatable_type', $owner->type)->where('authenticatable_id', $owner->key)->first()->consecutive_failures ?? 0;
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Models\Factor  $factor
     * @return int
     */
    protected function factorRun(Factor $factor): int
    {
        return Factor::query()->whereKey($factor->id)->sole()->getConsecutiveFailures();
    }

    /**
     * @return void
     */
    protected function forgetReports(): void
    {
        $this->reported = [];
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Events\VerificationFailed
     */
    protected function failureReported(): VerificationFailed
    {
        $failures = array_values(array_filter($this->reported, static fn (MfaEvent $event): bool => $event instanceof VerificationFailed));

        Assert::assertCount(1, $failures, 'Exactly one failure must be reported.');
        Assert::assertInstanceOf(VerificationFailed::class, $failures[0]);

        return $failures[0];
    }

    /**
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @param  string  $session
     * @param  \SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @return array<string, string>
     */
    protected function bindingOf(TestUser $user, string $session, Purpose $purpose): array
    {
        $owner = ProofOwner::of($user);

        return (new ProofBinding($owner->type, $owner->key, self::APPLICATION, $session, $purpose))->toArray();
    }

    /**
     * @return \SineMacula\Laravel\Mfa\MfaManager
     */
    protected function mfa(): MfaManager
    {
        $manager = $this->container()->make('mfa');

        Assert::assertInstanceOf(MfaManager::class, $manager);

        return $manager;
    }
}
