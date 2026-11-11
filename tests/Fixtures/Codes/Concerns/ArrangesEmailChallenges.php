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
 * Arranges email code challenges for a signed-in person with a confirmed email
 * factor.
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
    /** @var string */
    protected const string CHALLENGE_APPLICATION = 'web';

    /** @var string */
    protected const string CHALLENGE_SESSION = 'sign-in-1';

    /** @var string */
    protected const string ADDRESS = 'challenged@example.test';

    /**
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
