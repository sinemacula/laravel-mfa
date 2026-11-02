<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Codes\Concerns;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Testing\FakeEmailSender;
use Tests\Fixtures\Identities\TestUser;

/**
 * Arranges delivered code challenges: the `web` application with email codes
 * and a declared password first factor, a fake email sender, and a signed-in
 * person with a sign-in the proof store knows and a confirmed email factor.
 *
 * @phpstan-require-extends \Tests\TestCase
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait ArrangesEmailChallenges
{
    /** @var string The application the challenges are on. */
    protected const string CHALLENGE_APPLICATION = 'web';

    /** @var string The session id of the person's sign-in. */
    protected const string CHALLENGE_SESSION = 'sign-in-1';

    /** @var string The person's email address. */
    protected const string ADDRESS = 'challenged@example.test';

    /**
     * Configure the application and the fake sender, and sign a person in with
     * a confirmed email factor; return the person, their factor and the fake.
     *
     * @return array{\Tests\Fixtures\Identities\TestUser, \SineMacula\Laravel\Mfa\Models\Factor, \SineMacula\Laravel\Mfa\Testing\FakeEmailSender}
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    protected function arrangeEmailChallenges(): array
    {
        config()->set('mfa.applications.' . self::CHALLENGE_APPLICATION, [
            'types'        => ['email'],
            'first_factor' => ['method' => 'password', 'channel' => 'password'],
        ]);

        $mailbox = FakeEmailSender::fake($this->container());

        /** @var \Tests\Fixtures\Identities\TestUser $user */
        $user = TestUser::query()->create(['email' => self::ADDRESS]);

        $this->actingAs($user);

        $this->container()->make(ProofStore::class)->begin($user, self::CHALLENGE_APPLICATION, self::CHALLENGE_SESSION);

        /** @var \SineMacula\Laravel\Mfa\Models\Factor $factor */
        $factor = Factor::query()->create([
            'authenticatable_type' => $user->getMorphClass(),
            'authenticatable_id'   => (string) $user->getKey(),
            'type'                 => 'email',
            'destination'          => self::ADDRESS,
            'status'               => 'confirmed',
            'confirmed_at'         => CarbonImmutable::now(),
            'application'          => self::CHALLENGE_APPLICATION,
        ]);

        return [$user, $factor, $mailbox];
    }

    /**
     * What the person's challenges are bound to on their sign-in.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @param  \SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @return \SineMacula\Laravel\Mfa\Proofs\ProofBinding
     */
    protected function emailBinding(TestUser $user, Purpose $purpose = Purpose::SIGN_IN): ProofBinding
    {
        $owner = ProofOwner::of($user);

        return new ProofBinding($owner->type, $owner->key, self::CHALLENGE_APPLICATION, self::CHALLENGE_SESSION, $purpose);
    }

    /**
     * The code last emailed to the person.
     *
     * @param  \SineMacula\Laravel\Mfa\Testing\FakeEmailSender  $mailbox
     * @return string
     */
    protected static function lastEmailedCode(FakeEmailSender $mailbox): string
    {
        $code = $mailbox->lastCodeTo(self::ADDRESS);

        Assert::assertNotNull($code, 'A code was expected to have been emailed.');

        return $code;
    }
}
