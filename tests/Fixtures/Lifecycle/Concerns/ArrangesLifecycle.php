<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Lifecycle\Concerns;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Event;
use SineMacula\Laravel\Mfa\Contracts\MfaEvent;
use SineMacula\Laravel\Mfa\Enrollment\PendingEnrollments;
use SineMacula\Laravel\Mfa\Enums\EnrollmentAuthorization;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Events\Actor;
use SineMacula\Laravel\Mfa\Models\Enrollment;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Passkeys\Concerns\ArrangesPasskeys;

/**
 * Arranges the lifecycle tests on top of the passkey arrangements, recording
 * every event the package reports.
 *
 * @phpstan-require-extends \Tests\TestCase
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait ArrangesLifecycle
{
    use ArrangesPasskeys;

    /** @var list<\SineMacula\Laravel\Mfa\Contracts\MfaEvent> Oldest first. */
    private array $reported = [];

    /**
     * @param  array<string, mixed>  $settings
     * @return void
     */
    protected function arrangeLifecycle(array $settings = []): void
    {
        config()->set('hashing.bcrypt.rounds', 4);

        CarbonImmutable::setTestNow(CarbonImmutable::createFromTimestamp(1800000015));

        $this->enablePasskeys(['recovery_codes' => ['enabled' => true], ...$settings]);

        Event::listen(MfaEvent::class, function (MfaEvent $event): void {
            $this->reported[] = $event;
        });
    }

    /**
     * @return list<string>
     */
    protected function reportedNames(): array
    {
        return array_map(static fn (MfaEvent $event): string => class_basename($event), $this->reported);
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Events\Actor
     */
    protected static function actor(): Actor
    {
        return new Actor('admin', '9');
    }

    /**
     * Clears what was reported.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @return void
     *
     * @throws \Throwable
     */
    protected function recoveryCodesOf(TestUser $user): void
    {
        $this->container()->make(RecoveryCodeService::class)->generate($user, 'web');

        $this->reported = [];
    }

    /**
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @param  ?\Carbon\CarbonImmutable  $expiresAt
     * @return array{\SineMacula\Laravel\Mfa\Models\Factor, \SineMacula\Laravel\Mfa\Models\Enrollment}
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    protected function pendingEnrollmentOf(TestUser $user, ?CarbonImmutable $expiresAt = null): array
    {
        $factor = $this->confirmedFactor($user);

        $factor->update(['status' => 'pending', 'confirmed_at' => null]);

        $enrollment = $this->container()->make(PendingEnrollments::class)->create(
            $factor->id,
            hash('sha256', $factor->id),
            $this->bindingOf($user, Purpose::ENROLLMENT),
            VerificationGeneration::current($user),
            EnrollmentAuthorization::STEP_UP,
            $expiresAt ?? CarbonImmutable::now()->addMinutes(10),
        );

        return [$factor, $enrollment];
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Models\Factor  $factor
     * @return bool
     */
    protected function isStored(Factor $factor): bool
    {
        return Factor::query()->whereKey($factor->id)->exists();
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Models\Enrollment  $enrollment
     * @return bool
     */
    protected function isEnrollmentStored(Enrollment $enrollment): bool
    {
        return Enrollment::query()->whereKey($enrollment->id)->exists();
    }
}
