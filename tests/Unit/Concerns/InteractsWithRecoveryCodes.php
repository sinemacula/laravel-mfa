<?php

declare(strict_types = 1);

namespace Tests\Unit\Concerns;

use Illuminate\Config\Repository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Auth;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Models\IdentityState;
use SineMacula\Laravel\Mfa\Models\RecoveryCode;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService;
use SineMacula\Laravel\Mfa\Secrets\RevealedSecret;
use Tests\Fixtures\Identities\FactorHolder;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait InteractsWithRecoveryCodes
{
    /**
     * Cheapest bcrypt cost so a set hashes quickly.
     *
     * @param  mixed  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(Repository::class);

        $config->set('hashing.bcrypt.rounds', 4);
        $config->set('mfa.applications.web', [
            'recovery_codes' => ['enabled' => true],
            'first_factor'   => ['method' => 'password', 'channel' => 'password'],
        ]);
    }

    /**
     * Signing in begins the sign-in a redemption records its proof on.
     *
     * @param  string  $email
     * @param  ?string  $status
     * @return \Tests\Fixtures\Identities\FactorHolder
     */
    protected function signInHolder(string $email = 'holder@example.com', ?string $status = 'confirmed'): FactorHolder
    {
        /** @var \Tests\Fixtures\Identities\FactorHolder $holder */
        $holder = FactorHolder::query()->create(['email' => $email]);

        if ($status !== null) {
            $this->addFactor($holder, $status);
        }

        Auth::login($holder);

        return $holder;
    }

    /**
     * @param  \Tests\Fixtures\Identities\FactorHolder  $holder
     * @param  string  $status
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    protected function addFactor(FactorHolder $holder, string $status = 'confirmed'): Factor
    {
        /** @var \SineMacula\Laravel\Mfa\Models\Factor */
        return Factor::query()->create([
            'authenticatable_type' => $holder->getMorphClass(),
            'authenticatable_id'   => (string) $holder->id,
            'type'                 => 'totp',
            'status'               => $status,
        ]);
    }

    /**
     * @return \SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    protected function recoveryCodes(): RecoveryCodeService
    {
        return $this->container()->make(RecoveryCodeService::class);
    }

    /**
     * @param  \Tests\Fixtures\Identities\FactorHolder  $holder
     * @param  \SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @return \SineMacula\Laravel\Mfa\Proofs\ProofBinding
     */
    protected static function redemptionBinding(FactorHolder $holder, Purpose $purpose = Purpose::SIGN_IN): ProofBinding
    {
        return new ProofBinding($holder->getMorphClass(), (string) $holder->id, 'web', 'redemption-sign-in', $purpose);
    }

    /**
     * @param  list<\SineMacula\Laravel\Mfa\Secrets\RevealedSecret>  $codes
     * @return list<string>
     */
    protected static function plaintexts(array $codes): array
    {
        return array_map(static fn (RevealedSecret $code): string => $code->reveal(), $codes);
    }

    /**
     * Oldest first.
     *
     * @param  \Tests\Fixtures\Identities\FactorHolder  $holder
     * @return \Illuminate\Support\Collection<int, \SineMacula\Laravel\Mfa\Models\RecoveryCode>
     */
    protected function storedCodes(FactorHolder $holder): Collection
    {
        /** @var \Illuminate\Support\Collection<int, \SineMacula\Laravel\Mfa\Models\RecoveryCode> */
        return RecoveryCode::query()
            ->where('authenticatable_type', $holder->getMorphClass())
            ->where('authenticatable_id', (string) $holder->id)
            ->orderBy('generation')
            ->orderBy('id')
            ->get()
            ->toBase();
    }

    /**
     * @param  \Tests\Fixtures\Identities\FactorHolder  $holder
     * @return \SineMacula\Laravel\Mfa\Models\IdentityState
     */
    protected function stateOf(FactorHolder $holder): IdentityState
    {
        /** @var \SineMacula\Laravel\Mfa\Models\IdentityState */
        return IdentityState::query()
            ->where('authenticatable_type', $holder->getMorphClass())
            ->where('authenticatable_id', (string) $holder->id)
            ->firstOrFail();
    }
}
