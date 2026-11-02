<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Passkeys\Concerns;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Assurance\Channel;
use SineMacula\Laravel\Mfa\Assurance\ObservedProperties;
use SineMacula\Laravel\Mfa\Contracts\PasskeyGateway;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Models\PasskeyAssociation;
use SineMacula\Laravel\Mfa\Passkeys\CredentialId;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyRegistration;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Passkeys\FakePasskeyGateway;

/**
 * Arranges the passkey tests: the `web` application with passkeys and TOTP
 * enabled, a declared password first factor and a fake passkey gateway; a
 * signed-in person with a sign-in the proof store knows; their confirmed
 * factors, a passkey with its association; a step-up recorded with one of
 * them; and a registration bound to their sign-in.
 *
 * @phpstan-require-extends \Tests\TestCase
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait ArrangesPasskeys
{
    /** @var string The application the passkeys are used on. */
    protected const string APPLICATION = 'web';

    /** @var string The session id of the person's sign-in. */
    protected const string SESSION = 'sign-in-1';

    /** @var string A canonical credential id. */
    protected const string CREDENTIAL = 'Y3JlZGVudGlhbC1vbmU';

    /** @var string Another canonical credential id. */
    protected const string OTHER_CREDENTIAL = 'Y3JlZGVudGlhbC10d28';

    /**
     * Enable passkeys and TOTP on the application with a declared password
     * first factor and any further settings given, and bind a fake gateway
     * listing the given credentials.
     *
     * @param  array<string, mixed>  $settings
     * @param  list<string>  $registered
     * @return \Tests\Fixtures\Passkeys\FakePasskeyGateway
     */
    protected function enablePasskeys(array $settings = [], array $registered = []): FakePasskeyGateway
    {
        config()->set('mfa.applications.' . self::APPLICATION, array_replace([
            'types'        => ['totp', 'passkey'],
            'first_factor' => ['method' => 'password', 'channel' => 'password'],
        ], $settings));

        $gateway = new FakePasskeyGateway($registered);

        $this->container()->instance(PasskeyGateway::class, $gateway);

        return $gateway;
    }

    /**
     * A person, signed in through the guard, with a sign-in on the application
     * the proof store knows.
     *
     * @param  string  $email
     * @return \Tests\Fixtures\Identities\TestUser
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    protected function signedInPerson(string $email = 'person@example.test'): TestUser
    {
        /** @var \Tests\Fixtures\Identities\TestUser $user */
        $user = TestUser::query()->create(['email' => $email]);

        $this->actingAs($user);

        $this->container()->make(ProofStore::class)->begin($user, self::APPLICATION, self::SESSION);

        return $user;
    }

    /**
     * A confirmed factor of the user's, enrolled through the application; a
     * passkey is associated with its credential.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @param  string  $type
     * @param  ?string  $credential
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    protected function confirmedFactor(TestUser $user, string $type = 'totp', #[\SensitiveParameter] ?string $credential = null): Factor
    {
        /** @var \SineMacula\Laravel\Mfa\Models\Factor $factor */
        $factor = Factor::query()->create([
            'authenticatable_type' => $user->getMorphClass(),
            'authenticatable_id'   => (string) $user->getKey(),
            'type'                 => $type,
            'status'               => 'confirmed',
            'confirmed_at'         => CarbonImmutable::now(),
            'credential_reference' => $credential,
            'application'          => self::APPLICATION,
        ]);

        if ($credential !== null) {
            PasskeyAssociation::query()->create([
                'factor_id'            => $factor->id,
                'authenticatable_type' => $user->getMorphClass(),
                'authenticatable_id'   => (string) $user->getKey(),
                'credential_id_hash'   => CredentialId::hash($credential),
                'credential_id'        => $credential,
            ]);
        }

        return $factor;
    }

    /**
     * Record a proof the user made with the factor on its sign-in, the given
     * number of seconds ago.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @param  \SineMacula\Laravel\Mfa\Models\Factor  $factor
     * @param  int  $secondsAgo
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    protected function stepUpWith(TestUser $user, Factor $factor, int $secondsAgo = 0): void
    {
        $channel = $factor->type === 'passkey'
            ? new Channel(ChannelKind::PASSKEY, $factor->credential_reference)
            : new Channel(ChannelKind::AUTHENTICATOR_APP, $factor->id);

        $this->container()->make(ProofStore::class)->record(new Proof(
            kind      : ProofKind::ADDITIONAL_FACTOR,
            method    : $factor->type,
            channel   : $channel,
            reference : $factor->id,
            properties: new ObservedProperties(userPresence: $factor->type === 'passkey' ? true : null),
            provedAt  : CarbonImmutable::now()->subSeconds($secondsAgo),
            binding   : $this->bindingOf($user, Purpose::STEP_UP),
            generation: VerificationGeneration::current($user),
        ));
    }

    /**
     * A registration of the credential bound to the user's enrolment on its
     * sign-in, observing the properties given or user presence alone.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @param  string  $credential
     * @param  ?\SineMacula\Laravel\Mfa\Assurance\ObservedProperties  $properties
     * @param  string  $session
     * @return \SineMacula\Laravel\Mfa\Passkeys\PasskeyRegistration
     */
    protected function registration(
        TestUser $user,
        #[\SensitiveParameter] string $credential = self::CREDENTIAL,
        ?ObservedProperties $properties = null,
        string $session = self::SESSION,
    ): PasskeyRegistration {
        return new PasskeyRegistration($credential, $properties ?? new ObservedProperties(userPresence: true), $this->bindingOf($user, Purpose::ENROLLMENT, $session));
    }

    /**
     * What a proof of the user's on the application's sign-in is bound to.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @param  \SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @param  string  $session
     * @return \SineMacula\Laravel\Mfa\Proofs\ProofBinding
     */
    protected function bindingOf(TestUser $user, Purpose $purpose, string $session = self::SESSION): ProofBinding
    {
        $owner = ProofOwner::of($user);

        return new ProofBinding($owner->type, $owner->key, self::APPLICATION, $session, $purpose);
    }
}
